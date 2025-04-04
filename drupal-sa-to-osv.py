import json
import os
import shutil
import subprocess
from datetime import datetime
import requests
import feedparser
import pprint
import semver
import time

repo_url = "https://github.com/CVEProject/cvelistV5.git"
cve_dir_name = "cvelistV5"
osv_dir_name = "advisories"
# Not all fields pass the schema test as there are elements that are not yet present in the OSV schema.
full_proposed_entry = False

pp = pprint.PrettyPrinter(indent=2)

# Ensure we have the source data.
def clone_repo_if_not_exists(repo_url, dir_name):
    if not os.path.exists(dir_name):
        print(f"Directory '{dir_name}' not found. Cloning repository...")
        print(f"Cloning '{repo_url}' into '{dir_name}'...")
        print("This may take a while...")
        subprocess.run(["git", "clone", repo_url, dir_name])
    else:
        print(f"Pulling latest changes from '{repo_url}'...")
        subprocess.run(["git", "pull"], cwd=dir_name)

# Some of the date strings in the cve files are not in the correct format for the OSV schema.
def format_datetime(date_str):
    if date_str[-1] == 'Z':
        return date_str
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def datetime_to_timestamp(date_str):
    return int(time.mktime(datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ").timetuple()))

def datetime_from_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def osv_template(sa_id):

    return {
        "schema_version": "1.3.0",
        "id": '',
        "modified": '',
        "published": '',
        "aliases": [],
        "related": [],
        "summary": '',
        "details": '',
        "affected": [
            {
                "package": {
                    "ecosystem": "Drupal",
                    "name": ''
                },
                "severity": [{
                    "type": "NIST_CMSS",
                    "score": ""
                }],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            # {
                            #     "introduced": cve['containers']['cna']['affected'][0]['versions'][0]['version']
                            # },
                            # {
                            #     "fixed": cve['containers']['cna']['affected'][0]['versions'][0]['version']
                            # }
                        ]
                    }
                ]
            }
        ],
        "references": [
            # {
            #     "type": "WEB",
            #     "url": ''
            # }
        ],
        "credits": []
    }

def project_dir_from_osv_entry(osv_dir_name, osv_entry):
    dir = os.path.join(osv_dir_name, osv_entry['affected'][0]['package']['name'].split('/')[1])
    if not os.path.exists(dir):
        os.makedirs(dir)
    return dir

def write_osv_entry_to_file(osv_dir_name, osv_entry, id):
    output_file = os.path.join(project_dir_from_osv_entry(osv_dir_name, osv_entry), f"osv-{id.lower()}.json")
    with open(output_file, 'w') as f:
        json.dump(osv_entry, f, indent=2)

def fetch_url_to_file(url, file_path):
    if os.path.exists(file_path):
        # print(f"File {file_path} already exists. Skipping fetch.")
        return

    response = requests.get(url)
    if response.status_code == 200:
        with open(file_path, 'wb') as file:
            file.write(response.content)
        print(f"Content fetched from {url} and written to {file_path}")
    else:
        print(f"Failed to fetch content from {url}. Status code: {response.status_code}")

# Fetch a node from drupal.org
def get_node(nid, type):
    dir = 'files'
    if not os.path.exists('files'):
        os.mkdir(dir)
    sa_url = f"https://www.drupal.org/api-d7/node.json?nid={nid}"
    sa_file = f"{dir}/{type}-{nid}.json"
    fetch_url_to_file(sa_url, sa_file)
    return json.loads(open(sa_file).read())

def preload_sa(nid):
    # @TODO: NID is unique. Check if we have one already. If so return True if it is a security advisory.
    content_types = ['sa', 'project_module', 'project_release']
    for content_type in content_types:
        if os.path.exists(f"files/{content_type}-{nid}.json"):
            if content_type == 'sa':
                return True
            else:
                return False

    node = get_node(nid, 'tmp')
    if len(node['list']) == 0:
        # Not sure what we have here. Skip it.
        print(f"Error?: Node {nid} has no content. Skipping.")
        pprint.pprint(node)
        return False

    tmp_file = f"files/tmp-{nid}.json"
    dest_file = f"files/{node['list'][0]['type']}-{nid}.json"

    if node['list'][0]['type'] in content_types:
        print(f"Moving {tmp_file} to {dest_file}")
        shutil.move(tmp_file, dest_file)
        if node['list'][0]['type'] == 'sa':
            return True
    return False

# Fetch the SA node from drupal.org
def get_sa_entry(nid):
    return get_node(nid, 'sa')

# Fetch the project node from drupal.org
def get_project_entry(nid):
    return get_node(nid, 'project_module')

# Fetch the Project Release node from drupal.org
def get_fixed_in_entry(nid):
    return get_node(nid, 'project_release')

# parse the affected versions string into a list of affected versions given a string like '>=3.0.0 <3.44.0 || >=4.0.0 <4.0.19'
def parse_affected_versions(affected_versions):
    affected = []
    for versions in affected_versions.split(' || '):
        # split version on space and append the first element to the affected list after removing any > or >= characters.
        versions = versions.replace('>=', '').replace('>', '').replace('< ', '<').replace('= ', '=').strip()
        introduced = versions.split()[0].strip()
        if introduced[0] == '<':
            introduced = '0.0.0'
        introduced = introduced.replace('*', '0')
        affected.append({'introduced': introduced})
        if len(versions.split()) > 1:
            # It looks like Core does not have field_fixed_in populated. Add a
            # fixed version from this string if we can.
            fixed = versions.split()[1].replace('<', '').replace('=', '').strip()
            affected.append({'fixed': fixed})
    return affected

def fake_ecosystem(osv_entry):
    if not full_proposed_entry:
        # Fake the package.ecosystem so a schema validator doesn't complain.
        for affected in osv_entry['affected']:
            affected['package']['ecosystem'] = 'Packagist'
        # Fake the ID so it passes the schema validation.
        osv_entry['id'] = f"OSV-{osv_entry['id']}"
    return osv_entry

def add_fixed_in_versions(affected_versions, fixed_in_json):
    for fixed_in in fixed_in_json:
        for fixed_version in fixed_in['list']:
            fixed_major = fixed_version['field_release_version_major']
            fixed_minor = fixed_version['field_release_version_minor']
            fixed_patch = fixed_version['field_release_version_patch'] or '0'
            fixed_in_semver = f"{fixed_major}.{fixed_minor}.{fixed_patch}"
            affected_versions.append({'fixed': fixed_in_semver})
    return affected_versions

def check_for_fixed_versions(affected_versions, fixed_in_json):
    inserted = []
    for idx, val in enumerate(affected_versions):
        if 'introduced' not in val.keys():
            continue
        introduced = val['introduced'].replace('<', '').strip().split(".")
        # sanity check the length of the introduced value.
        while len(introduced) < 3:
            introduced.append("0")

        for i in range(3):
            if introduced[i].isnumeric():
                introduced[i] = int(introduced[i])
            else:
                introduced[i] = 0
        introduced_major = introduced[0]
        introduced_minor = introduced[1]
        introduced_patch = introduced[2]
        introduced = f"{introduced_major}.{introduced_minor}.{introduced_patch}"

        # Walk over the fixed_in_json and check if any of the fixed versions are for the current affected_version.
        for fixed_in in fixed_in_json:
            for fixed_version in fixed_in['list']:
                # if int(fixed_version['field_release_version_major']) != int(introduced_major):
                #     continue
                fixed_major = fixed_version['field_release_version_major']
                fixed_minor = fixed_version['field_release_version_minor']
                fixed_patch = fixed_version['field_release_version_patch'] or '0'
                fixed_in_semver = f"{fixed_major}.{fixed_minor}.{fixed_patch}"
                if fixed_in_semver in inserted:
                    # We have already inserted this one. Skip it so we don't end up in an infinite loop.
                    continue
                if int(introduced_major) == int(fixed_major) and semver.compare(fixed_in_semver, introduced) > 0:
                    # Insert the fixed after the current index.
                    idx += 1
                    affected_versions.insert(idx, {'fixed': fixed_in_semver})
                    inserted.append(fixed_in_semver)
    return affected_versions

def semver_for_sorting(semver):
    decrement_semver = False
    if semver == '':
        return ''
    # Check if the semver string starts with a '<' character.
    if semver[0] == '<':
        decrement_semver = True
        semver = semver[1:]
    semver = semver.strip().split(".")
    # sanity check the length of the introduced value.
    while len(semver) < 3:
        semver.append("0")

    for i in range(3):
        if semver[i].isnumeric():
            semver[i] = int(semver[i])
        else:
            semver[i] = 0

    if decrement_semver:
        if semver[2] > 0:
            semver[2] -= 1
        elif semver[1] > 0:
            semver[1] -= 1

    semver_major = semver[0]
    semver_minor = semver[1]
    semver_patch = semver[2]
    return f"{semver_major}.{semver_minor}.{semver_patch}"

def sort_affected_versions(affected_versions):
    sorted_versions = {}
    return_values = []
    for affected in affected_versions:
        if 'introduced' in affected.keys():
            sorted_versions[semver_for_sorting(affected['introduced'])] = affected
        if 'fixed' in affected.keys():
            sorted_versions[semver_for_sorting(affected['fixed'])] = affected

    # sort the dict by the keys assuming the keys are semver strings.
    sorted_versions = dict(sorted(sorted_versions.items(), key=lambda item: semver.parse_version_info(item[0])))
    for key in sorted_versions.keys():
        return_values.append(sorted_versions[key])

    return return_values

# Drupal uses the NIST's Common Misuse Scoring System (CMSS) to calculate the severity of a security advisory.
# We will want to get this added to the OSV security[].type field.
# Turns out the actual string is what should go in the field. I will leave this here for reference and in case we need the numeric value later.
def calculate_severity(criticality):
    score = 0
    severity_matrix = {
        'ac': {
            'none': 4,
            'basic': 2,
            'complex': 1,
        },
        'a': {
            'none': 4,
            'user': 2,
            'admin': 1,
        },
        'ci': {
            'all': 5,
            'some': 3,
            'none': 0,
        },
        'ii': {
            'all': 5,
            'some': 3,
            'none': 0,
        },
        'e': {
            'exploit': 4,
            'proof': 2,
            'theoretical': 1,
        },
        'td': {
            'all': 3,
            'default': 2,
            'uncommon': 1,
        },
    }
    for check in criticality.lower().split('/'):
        [key, value] = check.split(':')
        score += severity_matrix[key][value]
    return f"{score}"

# Convert the severity score to a string.
def severity_string(score):
    if score <= 4:
        return 'Not Critical'
    elif score <= 9:
        return 'Less Critical'
    elif score <= 14:
        return 'Moderately Critical'
    elif score <= 19:
        return 'Critical'
    elif score <= 25:
        return 'Highly Critical'
    else:
        return 'Score Error'

def get_credits_from_sa(credits):
    credit_list = []

    # Sanity checks.
    if len(credits) == 0 or 'value' not in credits.keys():
        return credit_list
    # The credits['value'] is a sting with an ordered list of credits.
    # A credit is a link to the user's profile on drupal.org with the user's name as the link text.
    for credit in credits['value'].replace('<ul>', '').replace('</ul>', '').strip().split('<li>'):
        credit = credit.replace('</li>', '').strip()
        if '<a' in credit:
            href = credit.split('href="')[1].split('"')[0]
            name = credit.split('">')[1].split('</a>')[0]
            credit_list.append({
                'name': name,
                'contact': [href]
            })

    return credit_list

def get_last_osv_modified_timestamp():
    # fetch all json files in the osv directory and the subdirectories.
    highest_modified = 0
    for root, dirs, files in os.walk(osv_dir_name):
        for file in files:
            if file.endswith(".json"):
                # Load the contents of the file into a dictionary.
                osv = json.loads(open(os.path.join(root, file)).read())
                modified = datetime_to_timestamp(osv['modified'])
                if modified > highest_modified or highest_modified == 0:
                    highest_modified = modified
    return highest_modified

# Walk over the cve files and convert them to OSV entries.
def build_osv_entries_from_cve(cve_dir_name, osv_dir_name, repo_url):
    clone_repo_if_not_exists(repo_url, cve_dir_name)
    # If the target osv directory does not exist, create it.
    if not os.path.exists(osv_dir_name):
        os.mkdir(osv_dir_name)
    for root, dirs, files in os.walk(f"{cve_dir_name}/cves/"):
        for file in files:
            if file.endswith(".json"):
                cve_file = os.path.join(root, file)
                # check if the file contents contains the string "drupal.org" in it.
                cve_string = open(cve_file).read()
                if "drupal.org" not in cve_string:
                    continue
                # Load the contents of cve_string into a dictionary.
                cve = json.loads(cve_string)
                # @TODO: Walk over all the references and check if they are drupal.org/node references.
                # If there are, fetch the node, check the type and process it if it is a security advisory.

                refs = cve['containers']['cna']['references']
                for ref in refs:
                    if 'tags' in ref.keys() and 'x_refsource_CONFIRM' in ref['tags'] and 'drupal.org/node/' in ref['url']:
                        if preload_sa(ref['url'].split('/')[-1]) == True:
                            process_sa(ref['url'].split('/')[-1])

# Fetch the SA data from drupal.org rss feed.
# https://www.drupal.org/security/all/rss.xml
def build_osv_entries_from_rss(osv_dir_name):
    # rss_file = "drupal-security-advisories.xml"
    rss_files = {
        "dsa-contrib.xml": "https://www.drupal.org/security/contrib/rss.xml",
        "dsa-core.xml": "https://www.drupal.org/security/rss.xml",
    }
    for rss_file, rss_url in rss_files.items():
        process_rss_feed(rss_file, rss_url)

def process_rss_feed(rss_file, rss_url):
    # Fetch the RSS feed and save it to a file.
    fetch_url_to_file(rss_url, rss_file)

    # Parse the feed and extract the SA data.
    feed = feedparser.parse(rss_file)

    for entry in feed.entries:
        print(f"Processing entry: {entry['id']}")
        process_sa(entry['id'].split()[0])

def composer_package(project_json):
    project_type = 'drupal'
    project_name = project_json['list'][0]['field_project_machine_name']
    if project_name == 'drupal':
        project_name = 'core'
    return f"{project_type}/{project_name}"

# This fetches a single SA from drupal.org and processes it.
def process_sa(sa_node_id):
    print("\n")
    print(f"Processing SA nid: {sa_node_id}")
    ## Get the node we need.
    sa_json = get_sa_entry(sa_node_id)
    process_sa_json(sa_json['list'][0])

# This processes the SA JSON data.
def process_sa_json(sa_json):
    if sa_json['field_is_psa'] == '1':
        # We can ignore PSA's.
        print(f"Skipping PSA: {sa_json['title']}")
        return
    if sa_json['field_affected_versions'] is None:
        # We can ignore SA's that do not have affected versions.
        print(f"Skipping SA without affected versions: {sa_json['title']}")
        print(f"SA URL: {sa_json['url']}")
        return

    sa_id = sa_json['url'].split('/')[-1].upper()
    osv_entry = osv_template(sa_id)
    project_json = None
    fixed_in_json = []

    if sa_json['field_project']['id'] != '0':
        project_json = get_project_entry(sa_json['field_project']['id'])

    if len(sa_json['field_fixed_in']) > 0:
        for fixed_in in sa_json['field_fixed_in']:
            fixed_in_json.append(get_fixed_in_entry(fixed_in['id']))

    if 'field_sa_reported_by' in sa_json.keys():
        osv_entry['credits'] = get_credits_from_sa(sa_json['field_sa_reported_by'])

    osv_entry['id'] = f"{sa_id}"

    # TODO: Add the severity to the OSV entry.
    # https://ossf.github.io/osv-schema/#severitytype-field
    # https://www.drupal.org/drupal-security-team/security-risk-levels-defined
    # https://www.nist.gov/news-events/news/2012/07/software-features-and-inherent-risks-nists-guide-rating-software
    if full_proposed_entry:
        osv_entry['affected'][0]['severity'][0]['score'] = sa_json['field_sa_criticality']
    else:
        osv_entry['affected'][0]['severity'] = []

    osv_entry['affected'][0]['package']['name'] = composer_package(project_json)
    osv_entry['published'] = datetime.fromtimestamp(int(sa_json['created'])).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    osv_entry['modified'] = datetime.fromtimestamp(int(sa_json['changed'])).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    affected_versions = parse_affected_versions(sa_json['field_affected_versions'])
    affected_versions = add_fixed_in_versions(affected_versions, fixed_in_json)
    affected_versions = sort_affected_versions(affected_versions)
    if len(affected_versions) > 0:
        for affected in affected_versions:
            for [event, version] in affected.items():
                osv_entry['affected'][0]['ranges'][0]['events'].append({event: version})

    if len(sa_json['field_sa_cve']) > 0:
        for cve in sa_json['field_sa_cve']:
            osv_entry['aliases'].append(cve)

    osv_entry['details'] = sa_json['field_sa_description']['value']
    osv_entry['references'].append({
        'type': 'WEB',
        'url': sa_json['url']
    })

    fake_ecosystem(osv_entry)
    write_osv_entry_to_file(osv_dir_name, osv_entry, f"{sa_id}")

def build_osv_entries_from_rest_api(last_modified_timestamp):
    url = "https://www.drupal.org/api-d7/node.json?type=sa&sort=changed&direction=DESC&field_is_psa=0"
    fetch_again = True
    while fetch_again:
        print(f"Fetching {url}")
        response = requests.get(url)
        print(f"Status code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            for item in data['list']:
                changed = int(item['changed'])
                if changed > last_modified_timestamp:
                    process_sa_json(item)
                else:
                    # We have reached the last modified entry.
                    fetch_again = False
            if 'next' in data.keys() and data['next'] != "":
                url = data['next'].replace('api-d7/node?', 'api-d7/node.json?')
            else:
                print("No more pages to fetch.")
                fetch_again = False
        else:
            print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
            pp.pprint(response.headers)
            fetch_again = False

# Processing...
last_modified_timestamp = get_last_osv_modified_timestamp()
build_osv_entries_from_rest_api(last_modified_timestamp)
# build_osv_entries_from_rss(osv_dir_name)
# Ignore CVEs for now. Finding a valid Security Advisory on the older ones is a bit of a challenge.
# Possibly check the node type and process if it is a security advisory.
# build_osv_entries_from_cve(cve_dir_name, osv_dir_name, repo_url)
