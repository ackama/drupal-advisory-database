import os

user_agent = 'drupal-advisory-database/'
if 'CI' in os.environ:
  user_agent += 'ci'
else:
  user_agent += 'local'
