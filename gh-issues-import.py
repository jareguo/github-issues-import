#!/usr/bin/env python3

import argparse
import base64
import time
import configparser
import getpass
import json
import os
import re
import sys
import urllib.request
import urllib.error
import urllib.parse

from collections import defaultdict, OrderedDict, namedtuple
from datetime import datetime
from string import Template


__location__ = os.path.realpath(os.path.join(os.getcwd(),
								os.path.dirname(__file__)))
DEFAULT_CONFIG_FILE = os.path.join(__location__, 'config.ini')

config = defaultdict(dict)

# timestamp format for ISO-8601 timestamps in UTC
ISO_8601_UTC = '%Y-%m-%dT%H:%M:%SZ'

# Regular expression for matching issue cross-references in GitHub issue and
# comment text.  I can't find any documentation on GitHub as to what the
# allowed characters are in repositories and usernames, but this seems like a
# good-enough guess for now
GH_ISSUE_REF_RE = re.compile(r'(?:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?)#'
							 r'([1-9]\d*)', flags=re.I)

# TODO: Do something useful with state management; my thought is to break this
# into actual stages of the import process where each stage will be in its own
# function.  A decorator could be used to identify what stage each function
# represents, and it should be possible to resume the import from any stage
# (where stages that have already been performed would be converted to no-ops)
class state:
	current = ""
	INITIALIZING         = "script-initializing"
	LOADING_CONFIG       = "loading-config"
	FETCHING_ISSUES      = "fetching-issues"
	GENERATING           = "generating"
	IMPORT_CONFIRMATION  = "import-confirmation"
	IMPORTING            = "importing"
	IMPORT_COMPLETE      = "import-complete"
	COMPLETE             = "script-complete"

state.current = state.INITIALIZING


HTTP_ERROR_MESSAGES = {
	401: "ERROR: There was a problem during authentication.\n"
		 "Double check that your username and password are correct, and "
		 "that you have permission to read from or write to the specified "
		 "repositories.",
	404: "ERROR: Unable to find the specified repository.\n"
		 "Double check the spelling for the source and target repositories. "
		 "If either repository is private, make sure the specified user is "
		 "allowed access to it."
}
# Basically the same problem. GitHub returns 403 instead to prevent abuse.
HTTP_ERROR_MESSAGES[403] = HTTP_ERROR_MESSAGES[401]


# Maps command-line options to their associated config file options (if any)
CONFIG_MAP = {
	'username': {'section': 'login', 'option': 'username'},
	'password': {'section': 'login', 'option': 'password'},
	'sources': {'section': 'global', 'option': 'sources', 'multiple': True},
	'target': {'section': 'global', 'option': 'target'},
	'update_existing': {'section': 'global', 'option': 'update-existing'},
	'ignore_comments': {'section': 'global', 'option': 'import-comments',
						'negate': True},
	'ignore_milestone': {'section': 'global', 'option': 'import-milestone',
						 'negate': True},
	'ignore_labels': {'section': 'global', 'option': 'import-labels',
					  'negate': True},
	'ignore_assignee': {'section': 'global', 'option': 'import-assignee',
						'negate': True},
	'no_backrefs': {'section': 'global', 'option': 'create-backrefs',
					'negate': True},
	'close_issues': {'section': 'global', 'option': 'close-issues'},
	'import_issues': {'section': 'global', 'option': 'import-issues',
					  'multiple': True},
	'normalize_labels': {'section': 'global', 'option': 'normalize-labels'},
	'issue_template': {'section': 'format', 'option': 'issue-template'},
	'comment_template': {'section': 'format', 'option': 'comment-template'},
	'pull_request_template': {'section': 'format',
							  'option': 'comment-template'}
}


# Set of config option names that take boolean values; the options listed here
# can either be in the global section, or in per-repository sections
BOOLEAN_OPTS = set(['import-comments',  'import-milestone', 'import-labels',
					'import-assignee', 'create-backrefs', 'close-issues',
					'normalize-labels', 'update-existing'])

class Issue(namedtuple('Issue', ('repository', 'number'))):
	"""
	A namedtuple class representing a GitHub issue.  It has two fields: the
	repository name (as full username/repo pair) and the issue number as an
	int.
	"""

	def __str__(self):
		return '%s#%s' % self


def init_config(argv):
	"""
	Handle command-line and config file processing; returns a `dict` of
	configuration combined from the config file and command-line options,
	as well as any default values.
	"""

	config_defaults = {}

	conf_parser = argparse.ArgumentParser(add_help=False,
			description="Import issues from one GitHub repository into "
						"another.")

	config_group = conf_parser.add_mutually_exclusive_group(required=False)
	config_group.add_argument('--config',
			help="The location of the config file (either absolute, or "
				 "relative to the current working directory). Defaults to "
				 "`config.ini` found in the same folder as this script.")

	config_group.add_argument('--no-config', dest='no_config',
			action='store_true',
			help="No config file will be used, and the default `config.ini` "
				 "will be ignored. Instead, all settings are either passed "
				 "as arguments, or (where possible) requested from the user "
				 "as a prompt.")

	arg_parser = argparse.ArgumentParser(parents=[conf_parser])

	arg_parser.add_argument('-u', '--username',
			help="The username of the account that will create the new "
				 "issues. The username will not be stored anywhere if "
				 "passed in as an argument.")

	arg_parser.add_argument('-p', '--password',
			help="The password (in plaintext) of the account that will "
				 "create the new issues. The password will not be stored "
				 "anywhere if passed in as an argument.")

	arg_parser.add_argument('-s', '--sources', nargs='+',
			help="The source repository or repositories from which the "
				 "issues should be copied.  If given more than one repository "
				 "the issues are merged from all repositories, and inserted "
				 "into the target repository in chronological order of their "
				 "creation.  Each repository should be in the format "
				 "`user/repository`.")

	arg_parser.add_argument('-t', '--target',
			help="The destination repository which the issues should be "
				 "copied to. Should be in the format `user/repository`.")

	arg_parser.add_argument('--update-existing', dest='update_existing',
			action='store_true',
			help='If any of the selected issues are found to have already '
				 'been migrated from their sources to the target, rather '
				 'than ignore them, update the migrated issue with any new '
				 'changes to the original issue--in particular any comments '
				 'that were not previously migrated (if not '
				 '--ignore-comments)')

	arg_parser.add_argument('--ignore-comments', dest='ignore_comments',
			action='store_true', help="Do not import comments in the issue.")

	arg_parser.add_argument('--ignore-milestone', dest='ignore_milestone',
			action='store_true',
			help="Do not import the milestone attached to the issue.")

	arg_parser.add_argument('--ignore-labels', dest='ignore_labels',
			action='store_true',
			help="Do not import labels attached to the issue.")

	arg_parser.add_argument('--ignore-assignee', dest='ignore_assignee',
			action='store_true',
			help="Do not import the assignee to the issue.")

	arg_parser.add_argument('--no-backrefs', dest='no_backrefs',
			action='store_true',
			help="Do not reference original issues in migrated issues; "
				 "migrated issues will appear as though they were newly "
				 "created.")

	arg_parser.add_argument('--close-issues', dest='close_issues',
			action='store_true',
			help="Close original issues after they have been migrated.")

	arg_parser.add_argument('--issue-template',
			help="Specify a template file for use with issues.")

	arg_parser.add_argument('--comment-template',
			help="Specify a template file for use with comments.")

	arg_parser.add_argument('--pull-request-template',
			help="Specify a template file for use with pull requests.")

	arg_parser.add_argument('--normalize-labels', action='store_true',
			help="When creating new labels and merging with existing labels "
				 "normalize the label names by setting them to all lowercase "
				 "and replacing all whitespace with a single hyphen.")

	include_group = arg_parser.add_mutually_exclusive_group(required=True)
	include_group.add_argument('--all', dest='import_issues',
			action='store_const', const='all',
			help="Import all issues, regardless of state.")

	include_group.add_argument('--open', dest='import_issues',
			action='store_const', const='open',
			help="Import only open issues.")

	include_group.add_argument('--closed', dest='import_issues',
			action='store_const', const='closed',
			help="Import only closed issues.")

	include_group.add_argument('--migrated', dest='import_issues',
			action='store_const', const='migrated',
			help="Import only already migrated issues (use only in "
				 "conjunction with --update-existing)")

	include_group.add_argument('-i', '--issues', dest='import_issues',
			type=int, nargs='+', help="The list of issues to import.");


	# First parse arguments that affect reading the config files; use this to
	# set various defaults and then parse the remaining options
	conf_args, _ = conf_parser.parse_known_args(argv)

	# TODO: This could be simplified even more with smarter use of argparse,
	# but good enough for now; it's not terribly important that this be
	# beautiful.

	if conf_args.no_config:
		print("Ignoring default config file. You may be prompted for some "
			  "missing settings.")
	else:
		if conf_args.config:
			# Read default values out of the config file, if given--these
			# values may be overridden by command-line options
			config_file_name = conf_args.config
			if load_config_file(config_file_name):
				print("Loaded config options from '%s'" % config_file_name)
			else:
				sys.exit("ERROR: Unable to find or open config file '%s'" %
						 config_file_name)
		else:
			config_file_name = DEFAULT_CONFIG_FILE
			if load_config_file(config_file_name):
				print("Loaded options from default config file in '%s'" %
					  config_file_name)
			else:
				print("Default config file not found in '%s'" %
					  config_file_name)
				print("You may be prompted for some missing settings.")

		# Get global configuration defaults from 'global' and 'login', and
		# format sections of the config file
		for argname, config_map in CONFIG_MAP.items():
			section = config_map['section']
			option = config_map['option']

			val = config[section].get(option)
			if val is not None:
				if config_map.get('multiple'):
					# A multiple-value can either be comma-separated or split
					# across lines (but not both)
					for sep in ('\n', ','):
						if sep in val:
							val = [v.strip() for v in val.split(sep)
								   if v.strip()]
							break
					else:
						val = [val]
				elif config_map.get('negate'):
					val = not val
				config_defaults[argname] = val

	arg_parser.set_defaults(**config_defaults)

	args = arg_parser.parse_args(argv)

	# Now load parsed args in to config dict; would be nice if there were a
	# better way to do this than to loop over CONFIG_MAP a second time.
	for argname, config_map in CONFIG_MAP.items():
		section = config_map['section']
		option = config_map['option']

		val = getattr(args, argname, None)
		if hasattr(args, argname) and val is not None:
			if config_map.get('multiple'):
				if not isinstance(val, list):
					val = [val]
			elif config_map.get('negate'):
				val = not val
			config[section][option] = val

	# Make sure no required config values are missing
	sources = config['global'].get('sources')
	target = config['global'].get('target')

	if not sources:
		sys.exit("ERROR: There are no source repositories specified either in "
				 "the config file, or as a command-line argument.")
	if not target:
		sys.exit("ERROR: There is no target repository specified either in "
				 "the config file, or as an argument.")

	# GitHub seems to be case-insensitive wrt username/repository name, so
	# lowercase all repositories for consistency
	sources = config['global']['sources'] = [s.lower() for s in sources]
	target = config['global']['target'] = target.lower()

	for section in list(config):
		if section.startswith('repository:'):
			if section.lower() != section:
				config[section.lower()] = section
				del config[section]

	def get_server_for(repo):
		# Default to 'github.com' if no server is specified
		server = get_repository_option(repo, 'server')
		if server is None:
			server = 'github.com'
			set_repository_option(repo, 'server', 'github.com')

		# if SOURCE server is not github.com, then assume ENTERPRISE github
		# (yourdomain.com/api/v3...)
		if server == "github.com":
			api_url = "https://api.github.com"
		else:
			api_url = "https://%s/api/v3" % server

		set_repository_option(repo, 'url', '%s/repos/%s' % (api_url, repo))

	# Prompt for username/password if none is provided in either the config or an argument
	def get_credentials_for(repo):
		server = get_repository_option(repo, 'server')
		query_msg_1 = ("Do you wish to use the same credentials for the "
					   "target repository?")
		query_msg_2 = ("Enter your username for '%s' at '%s': " %
					   (repo, server))
		query_msg_3 = ("Enter your password for '%s' at '%s': " %
					   (repo, server))

		if get_repository_option(repo, 'username') is None:
			if config['login'].get('username'):
				username = config['login']['username']
			elif (repo == target and len(sources) == 1 and
					yes_no(query_msg_1)):
				# One target and one source, where credentials for the target
				# were not supplied--ask to use the same credentials
				# TODO: In principle we could modify the logic here to take one
				# set of credentials and ask for each source *and* the target
				# repos to reuse those credentials, but for now this is just
				# reproducing the functionality that existed for single-source
				source = sources[0]
				username = get_repository_option(source, 'username')
			else:
				username = get_username(query_msg_2)

			set_repository_option(repo, 'username', username)

		if get_repository_option(repo, 'password') is None:
			# Again, support using the same password as the source, only if
			# there was a single source
			# TODO: Again, this logic could be modified to work better across
			# multiple sources, but it's not a priority right now.
			if config['login'].get('password'):
				password = config['login']['password']
			elif (repo == target and len(sources) == 1):
				source = sources[0]
				source_username = get_repository_option(source, 'username')
				source_server = get_repository_option(source, 'server')

				target_username = get_repository_option(repo, 'username')
				target_server = get_repository_option(repo, 'server')

				if (repo == target and
						source_username == target_username and
						source_server == target_server):
					password = get_repository_option(source, 'password')
				else:
					password = get_password(query_msg_3)
			else:
				password = get_password(query_msg_3)

			set_repository_option(repo, 'password', password)

	for repo in sources + [target]:
		get_server_for(repo)
		get_credentials_for(repo)

	# Everything is here! Continue on our merry way...


def load_config_file(config_file_name):
	global config  # global statement not strictly needed; just informational

	cfg = configparser.ConfigParser()
	try:
		with open(config_file_name) as f:
			cfg.read_file(f)

		for section in cfg.sections():
			for option in cfg.options(section):
				if ((section == 'global' or
						section.startswith('repository:')) and
					 option in BOOLEAN_OPTS):
					config[section][option] = cfg.getboolean(section, option)
				else:
					config[section][option] = cfg.get(section, option)

		return True
	except (FileNotFoundError, IOError, configparser.Error):
		return False


def get_repository_option(repo, option, default=None):
	"""
	Looks up per-repository options in the configuration; if not found it just
	returns the global setting from the [global] config section.

	Note, there are some repository-specific options (namely 'url') that should
	*only* appear in repository-specific config sections.
	"""

	repo_sect = 'repository:' + repo
	if repo_sect in config and option in config[repo_sect]:
		section = repo_sect
	else:
		section = 'global'

	return config[section].get(option, default)


def set_repository_option(repo, option, value):
	"""Sets a repository-specific option in the config."""

	config['repository:' + repo][option] = value


def normalize_label_name(label):
	"""
	Lowercases a label name and replaces all whitespace with hyphens.
	"""

	label = label.lower()
	return re.sub(r'\s+', '-', label)


def format_date(datestring):
	# The date comes from the API in ISO-8601 format
	date = datetime.strptime(datestring, ISO_8601_UTC)
	date_format = config['format'].get('date', '%A %b %d, %Y at %H:%M GMT')
	return date.strftime(date_format)


def format_from_template(template_filename, template_data):
	template_file = open(template_filename, 'r')
	template = Template(template_file.read())
	return template.substitute(template_data)


def format_issue(template_data):
	default_template = os.path.join(__location__, 'templates', 'issue.md')
	template = config['format'].get('issue-template', default_template)
	return format_from_template(template, template_data)


def format_pull_request(template_data):
	default_template = os.path.join(__location__, 'templates',
									'pull_request.md')
	template = config['format'].get('pull_request_template', default_template)
	return format_from_template(template, template_data)


def format_comment(template_data):
	default_template = os.path.join(__location__, 'templates', 'comment.md')
	template = config['format'].get('comment_template', default_template)
	return format_from_template(template, template_data)


def send_request(repo, url, post_data=None, method=None):
	if post_data is not None:
		post_data = json.dumps(post_data).encode("utf-8")

	repo_url = get_repository_option(repo, 'url')
	full_url = "%s/%s" % (repo_url, url)
	req = urllib.request.Request(full_url, post_data)

	if method is not None:
		req.method = method

	username = get_repository_option(repo, 'username')
	password = get_repository_option(repo, 'password')
	auth = base64.urlsafe_b64encode(
			('%s:%s' % (username, password)).encode('utf-8'))
	req.add_header("Authorization", b'Basic ' + auth)
	req.add_header("Content-Type", "application/json")
	req.add_header("Accept", "application/json")
	req.add_header("User-Agent", "spacetelescope/github-issues-import")

	try:
		response = urllib.request.urlopen(req)
		json_data = response.read()
	except urllib.error.HTTPError as error:

		error_details = error.read()
		error_details = json.loads(error_details.decode("utf-8"))

		if error.code in HTTP_ERROR_MESSAGES:
			sys.exit(HTTP_ERROR_MESSAGES[error.code])
		else:
			error_message = ("ERROR: There was a problem importing the "
							 "issues.\n%s %s" % (error.code, error.reason))
			if 'message' in error_details:
				error_message += "\nDETAILS: " + error_details['message']
			if 'errors' in error_details:
				error_message += "\n" + str(error_details['errors'])
			sys.exit(error_message)

	return json.loads(json_data.decode("utf-8"))


def get_milestones(repo):
	"""
	Get all open milestones for repository.

	Returns an `OrderedDict` keyed on the milestone title.
	"""

	milestones = send_request(repo, "milestones?state=open")
	return OrderedDict((m['title'], m) for m in milestones)


def get_labels(repo):
	"""
	Get all labels for repository.

	Returns an `OrderedDict` keyed on label names.  If normalize-labels was
	specified in the configuration, this also normalizes all label names and
	ignores their original spellings.
	"""
	page = 1
	labels = []
	while True:
		next_labels = send_request(which, "labels?page=%s" % page)
		if next_labels:
			labels.extend(next_labels)
			page += 1
		else:
			break

	normalize = get_repository_option(repo, 'normalize-labels')
	labels_dict = OrderedDict()
	for label in labels:
		if normalize:
			name = normalize_label_name(label['name'])
		else:
			name = label['name']

		labels_dict[name] = label
	return labels_dict


def get_issue_by_id(repo, issue_id):
	"""Get single issue from repository."""

	issue = send_request(repo, "issues/%d" % issue_id)
	issue['repository'] = repo
	return issue


def get_issues_by_id(repo, issue_ids):
	"""Get list of issues from repository for multiple issue numbers."""

	return [get_issue_by_id(repo, int(issue_id)) for issue_id in issue_ids]


def get_issues(repo, state=None):
	"""
	Get all issues from repository.

	Optionally, only retrieve issues of in the specified state ('open' or
	'closed')."""

	issues = []
	page = 1
	print("Fetching issues from %s in state=%s" % (repo, state), end='', flush=True)
	while True:
		query_args = {'direction': 'asc', 'page': page}
		if state in ('open', 'closed', 'all'):
			query_args['state'] = state

		# TODO: Consider building this into send_request in the form of
		# optional kwargs or something
		query = urllib.parse.urlencode(query_args)
		new_issues = send_request(repo, 'issues?' + query)
		if not new_issues:
			break

		# Add a 'repository' key to each issue; although this information can
		# be gleaned from the issue data it's easier to include here explicitly
		for issue in new_issues:
			issue['repository'] = repo

		issues.extend(new_issues)
		print('.', end='', flush=True)
		page += 1

	print('', flush=True)
	return issues


def get_comments_on_issue(repo, issue):
	"""Get all comments on an issue in the specified repository."""

	if issue['comments'] != 0:
		return send_request(repo, "issues/%s/comments" % issue['number'])
	else :
		return []


def import_milestone(source):
	data = {
		"title": source['title'],
		"state": "open",
		"description": source['description'],
		"due_on": source['due_on']
	}

	target = config['global']['target']
	result_milestone = send_request(target, "milestones", source)
	print("Successfully created milestone '%s'" % result_milestone['title'])
	return result_milestone


def import_label(source):
	data = {
		"name": source['name'],
		"color": source['color']
	}
	
	target = config['global']['target']
	result_label = send_request(target, "labels", source)
	print("Successfully created label '%s'" % result_label['name'])
	return result_label


def import_comments(orig_issue_id, comments, issue_number, issue_map):
	result_comments = []
	source_repo = orig_issue_id.repository

	for comment in comments:
		body = fixup_cross_references(comment['body'], source_repo, issue_map)

		template_data = {}
		template_data['user_name'] = comment['user']['login']
		template_data['user_url'] = comment['user']['html_url']
		template_data['user_avatar'] = comment['user']['avatar_url']
		template_data['date'] = format_date(comment['created_at'])
		template_data['url'] =  comment['html_url']
		template_data['body'] = body

		new_comment = {'body': format_comment(template_data)}

		target = config['global']['target']
		result_comment = send_request(target, "issues/%s/comments" %
									  issue_number, new_comment)
		result_comments.append(result_comment)
		# we need a delay to prevent abuse rate limit
		time.sleep(1)
		print('.', end='', flush=True)

		if get_repository_option(source_repo, 'create-backrefs'):
			# Update the original comment to mark it as migrated, and link to
			# the migrated comment

			message = (
				'*Migrated to [%s#%s (comment)](%s) by '
				'[spacetelescope/github-issues-import]'
				'(https://github.com/spacetelescope/github-issues-import)*' %
				(target, issue_number, result_comment['html_url']))

			update = {'body': message + '\n\n' + comment['body']}
			send_request(source_repo, 'issues/comments/%s' % comment['id'],
						 update, 'PATCH')

	print('', flush=True)
	return result_comments


def fixup_cross_references(text, source_repo, issue_map):
	"""
	Before inserting new issues into the target repository, this checks the
	original issue body for references to other issues in the original
	repository *or* issues in any of the other source repositories being
	migrated from.

	This can't reasonably update every existing reference to the original
	issue, but it can ensure that all issue cross-references made in the new
	issue are internally consistent.

	This can also be used to update cross references in comments.
	"""

	def repl_issue_reference(matchobj):
		"""
		If a matched issue reference is to within the same repository,
		it is updated to explictly reference the source repository (rather
		than a 'bare' issue reference like '#42').  However, if the referenced
		issue is one of the other issues being migrated, then it updates the
		reference to point to the newly migrated issue.
		"""

		repo = matchobj.group(1) or source_repo
		issue_num = int(matchobj.group(2))

		issue = Issue(repo, issue_num)

		if issue in issue_map:
			# Update to reference another issue being migrated to the target
			# repository
			return '#' + str(issue_map[issue][1])
		else:
			return str(issue)

	return GH_ISSUE_REF_RE.sub(repl_issue_reference, text)


def import_new_issue(new_issue, issue_map):
	"""
	Perform actual migration of new issues, including updates to the original
	source issue.
	"""

	target = config['global']['target']
	old_issue = new_issue['origin']

	if 'milestone_object' in new_issue:
		new_issue['milestone'] = new_issue['milestone_object']['number']
		del new_issue['milestone_object']

	if 'label_objects' in new_issue:
		issue_labels = []
		for label in new_issue['label_objects']:
			issue_labels.append(label['name'])
		new_issue['labels'] = issue_labels
		del new_issue['label_objects']

	result_issue = send_request(target, "issues", new_issue)
	result_issue_id = Issue(target, result_issue['number'])

	source_repo, number = old_issue
	close_issue = get_repository_option(source_repo, 'close-issues')

	if close_issue:
		close_message = '; the original issue will be closed'
	else:
		close_message = ''

	print("Successfully created issue '%s'%s" % (result_issue['title'],
												 close_message))

	# Now update the original issue to mention the new issue.
	update = {}

	if get_repository_option(source_repo, 'create-backrefs'):
		orig_issue = get_issue_by_id(source_repo, int(number))
		message = (
			'Migrated to %s by [issues-import]'
			'(https://github.com/jareguo/github-issues-import)\n----' %
			str(result_issue_id))
		update['body'] = message + '\n\n' + orig_issue['body']

	if close_issue:
		update['state'] = 'closed'

	send_request(source_repo, 'issues/%s' % number, update, 'PATCH')
	print("> Updated original issue with mapping from %s -> %s" %
		  (old_issue, result_issue_id))

	if 'comments' in new_issue:
		result_comments = import_comments(old_issue, new_issue['comments'],
										  result_issue['number'], issue_map)
		print(" > Successfully added", len(result_comments), "comments.")

	if new_issue['state'] == 'closed':
		closed_issue = {'state': 'closed'}
		result_issue = send_request(target, "issues/%s" % result_issue['number'], closed_issue, method='PATCH')
		print("> Closed imported issue")

	# Return value is currently used only for debugging
	return result_issue


def import_updated_issue(orig_issue_id, issue_id, updates, issue_map):
	"""
	Push updates to an existing issue, including any new comments.
	"""

	comments = updates.pop('comments', [])

	if 'milestone_object' in updates:
		updates['milestone'] = updates['milestone_object']['number']

	if 'new_labels' in updates:
		issue_labels = []
		for label in updates['label_objects']:
			issue_labels.append(label['name'])
		updates['labels'] = issue_labels
		del updates['label_objects']
		del updates['new_labels']

	result_issue = send_request(issue_id.repository,
								'issues/%s' % issue_id.number, updates,
								'PATCH')

	print(" > Successfully updated", issue_map[orig_issue_id])

	if comments:
		result_comments = import_comments(orig_issue_id, comments,
										  issue_id.number, issue_map)
		print(" > Successfully added", len(result_comments), "new comments.")

	return result_issue


def make_new_issue(orig_issue_id, orig_issue, issue_map):
	"""
	Returns a dict representing a new issue to be inserted into the target
	repository, based on the source issue specified by orig_issue_id/orig_issue
	as loaded from the source repo.
	"""

	repo = orig_issue['repository']
	new_issue = {}
	new_issue['origin'] = orig_issue_id
	new_issue['title'] = orig_issue['title']

	# Temporary fix for marking closed issues
	if orig_issue['closed_at']:
		new_issue['state'] = 'closed'
	else:
		new_issue['state'] = 'open'

	import_assignee = get_repository_option(repo, 'import-assignee')
	if import_assignee and orig_issue.get('assignee'):
		new_issue['assignee'] = orig_issue['assignee']['login']

	num_comments = int(orig_issue.get('comments', 0))
	if (get_repository_option(repo, 'import-comments') and
			num_comments != 0):
		new_issue['comments'] = get_comments_on_issue(repo, orig_issue)

	import_milestone = get_repository_option(repo, 'import-milestone')
	if import_milestone and orig_issue.get('milestone') is not None:
		# Since the milestones' ids are going to differ, we will compare
		# them by title instead
		new_issue['milestone_object'] = orig_issue['milestone']

	import_labels = get_repository_option(repo, 'import-labels')
	normalize_labels = get_repository_option(repo, 'normalize-labels')
	if import_labels and orig_issue.get('labels') is not None:
		new_issue['label_objects'] = []
		for issue_label in orig_issue['labels']:
			if normalize_labels:
				issue_label['name'] = \
						normalize_label_name(issue_label['name'])

			new_issue['label_objects'].append(issue_label)

	orig_issue['body'] = fixup_cross_references(orig_issue['body'], repo,
												issue_map)

	template_data = {}
	template_data['user_name'] = orig_issue['user']['login']
	template_data['user_url'] = orig_issue['user']['html_url']
	template_data['user_avatar'] = orig_issue['user']['avatar_url']
	template_data['date'] = format_date(orig_issue['created_at'])
	template_data['url'] =  orig_issue['html_url']
	template_data['body'] = orig_issue['body']
	template_data['num_comments'] = num_comments

	if get_repository_option(repo, 'create-backrefs'):
		if ("pull_request" in orig_issue and
				orig_issue['pull_request']['html_url'] is not None):
			new_issue['body'] = format_pull_request(template_data)
		else:
			new_issue['body'] = format_issue(template_data)
	else:
		new_issue['body'] = orig_issue['body']

	return new_issue


# Note: This could also probably make use of the events API to determine
# updates to the original issue, but directly comparing to the migrated issue
# is just as easy, so...

def make_updated_issue(orig_issue_id, orig_issue, issue_map):
	"""
	Returns a dict containing updates to an issue that has already been
	migrated once, determined by checking the original issue and seeing if
	there are any new differences (including new comments on) the original
	issue compared to the issue when it was first migrated.
	"""

	target = config['global']['target']
	repo = orig_issue_id.repository

	migrated_issue_id = issue_map[orig_issue_id]
	migrated_issue = get_issue_by_id(target, migrated_issue_id.number)

	updated_issue = {}

	if orig_issue['title'] != migrated_issue['title']:
		updated_issue['title'] = orig_issue['title']

	if get_repository_option(repo, 'import-assignee'):
		orig_assignee = orig_issue.get('assignee') or {}
		migrated_assignee = migrated_issue.get('assignee') or {}

		if (orig_assignee.get('login') is not None and
				orig_assignee.get('login') != migrated_assignee.get('login')):
			updated_issue['assignee'] = orig_assignee['login']

	if get_repository_option(repo, 'import-milestone'):
		orig_milestone = orig_issue.get('milestone') or {}
		migrated_milestone = migrated_issue.get('milestone') or {}

		if (orig_milestone.get('title') is not None and
				orig_milestone.get('title') != migrated_milestone.get('title')):
			updated_issue['milestone_object'] = orig_milestone

	normalize_labels = get_repository_option(repo, 'normalize-labels')
	if get_repository_option(repo, 'import-labels'):
		for issue_label in orig_issue['labels']:
			if normalize_labels:
				issue_label['name'] = \
						normalize_label_name(issue_label['name'])

			# Note: We will update any new labels added to the original issue
			# by copying them over the the migrated issue.  However, if any
			# labels were later *deleted* from the original issue we do not
			# transfer the deletions over, which could have unintended
			# consequences
			for label in migrated_issue.get('labels', []):
				if normalize_labels:
					migrated_label_name = normalize_label_name(label['name'])
				else:
					migrated_label_name = label['name']

				if migrated_label_name == issue_label['name']:
					break
			else:
				# This label is newly applied to the issue since it was
				# migrated
				if 'new_labels' not in updated_issue:
					updated_issue['new_labels'] = []

				updated_issue['new_labels'].append(issue_label['name'])

			# We still want to keep all the existing labels in the list of
			# labels on this issue; when updating labels on an issue via the
			# API it does not perform a union or anything like that--it's all
			# or nothing.
			if 'label_objects' not in updated_issue:
				updated_issue['label_objects'] = []

			updated_issue['label_objects'].append(issue_label)

		# If there are no *new* labels then there is no need to update the
		# labels at all, so delete the label_objects list
		if ('new_labels' not in updated_issue and
				'label_objects' in updated_issue):
			del updated_issue['label_objects']

	migrated_re = re.compile(
			r'^\*Migrated to \[(%s)#(\d+) \(comment\)\].* by.*'
			r'spacetelescope/github-issues-import' % target)

	def comment_was_migrated(comment):
		for line in comment['body'].splitlines():
			if migrated_re.match(line):
				return True

		return False

	if get_repository_option(repo, 'import-comments'):
		update_comments = []
		orig_comments = get_comments_on_issue(repo, orig_issue)

		# Note: This does *not* check for *edits* to comments that have already
		# been migrated.  We could probably due it as well but there currently
		# isn't any use case...
		for comment in orig_comments:
			if not comment_was_migrated(comment):
				update_comments.append(comment)

		if update_comments:
			updated_issue['comments'] = update_comments

	return updated_issue


# Will only import milestones and issues that are in use by the imported
# issues, and do not exist in the target repository
def import_issues(issues, issue_map):
	state.current = state.GENERATING

	print("Preparing import for %d issues" % len(issues))

	target = config['global']['target']
	known_milestones = get_milestones(target)
	known_labels = get_labels(target)

	new_issues = []
	updated_issues = OrderedDict()
	skipped_issues = OrderedDict()

	num_new_comments = 0
	new_milestones = []
	new_labels = []

	for issue, old_issue in zip(issues, issue_map):
		repo = issue['repository']

		if issue['migrated']:
			if get_repository_option(repo, 'update-existing'):
				updated_issues[old_issue] = \
						make_updated_issue(old_issue, issue, issue_map)
			else:
				skipped_issues[old_issue] = issue
				continue
		else:
			new_issues.append(make_new_issue(old_issue, issue, issue_map))

	for issue in new_issues + list(updated_issues.values()):
		num_new_comments += len(issue.get('comments', []))
		# Find any new milestones or labels
		milestone = issue.get('milestone_object')
		if milestone:
			known_milestone = known_milestones.get(milestone['title'])
			if not known_milestone:
				new_milestones.append(milestone)
				known_milestones[milestone['title']] = milestone
			else:
				issue['milestone_object'] = known_milestone

		labels = issue.get('label_objects', [])
		for idx, label in enumerate(labels):
			known_label = known_labels.get(label['name'])
			if not known_label:
				new_labels.append(label)
				known_labels[label['name']] = label
			else:
				issue['label_objects'][idx] = known_label

	state.current = state.IMPORT_CONFIRMATION

	print("You are about to add to '%s':" % target)
	print(" *", len(new_issues), "new issues:")

	for old, new in issue_map.items():
		if old in skipped_issues or old in updated_issues:
			continue

		print("   *", old, "->", new)

	print(" *", num_new_comments, "new comments")
	print(" *", len(new_milestones), "new milestones")
	print(" *", len(new_labels), "new labels")

	if updated_issues:
		print("The following issues that were already migrated will be "
			  "updated:")
		for orig_issue_id, updates in updated_issues.items():
			if not updates:
				continue

			print(" *", orig_issue_id, "->", issue_map[orig_issue_id])
			if 'title' in updates:
				print("   * Title updated to:", updates['title'])
			if 'assignee' in updates:
				print("   * Assignee updated to:", updates['assignee'])
			if 'milestone_object' in updates:
				print("   * Milestone update to:",
					  updates['milestone_object']['title'])
			if 'new_labels' in updates:
				print("   * The following new labels will be added:")
				for label in updates['new_labels']:
					print("     *", label)
			if 'comments' in updates:
				print("   *", str(len(updates['comments'])),
					  "new comments added")

	if skipped_issues:
		print(" *", "The following issues look like they have already been "
					"migrated to the target repository by this script and "
					"will not be migrated:")
		for key, issue in skipped_issues.items():
			print ("   *", key)

    if not yes_no("Are you sure you wish to continue?"):
        sys.exit()

	state.current = state.IMPORTING

	for milestone in new_milestones:
		result_milestone = import_milestone(milestone)
		milestone['number'] = result_milestone['number']
		milestone['url'] = result_milestone['url']

	for label in new_labels:
		result_label = import_label(label)

	for new_issue in new_issues:
		result_issue = import_new_issue(new_issue, issue_map)
		# delay to prevent abuse rate limit
		time.sleep(1)

	for orig_issue_id, updated_issue in updated_issues.items():
		if not updated_issue:
			continue

		result_issue = import_updated_issue(orig_issue_id,
											issue_map[orig_issue_id],
											updated_issue, issue_map)
		# delay to prevent abuse rate limit
		time.sleep(1)

	state.current = state.IMPORT_COMPLETE


def get_username(question):
	# Reserve this are in case I want to prevent special characters etc in the future
	return input(question)


def get_password(question):
	return getpass.getpass(question)


# Taken from http://code.activestate.com/recipes/577058-query-yesno/
#  with some personal modifications
def yes_no(question, default=True):
	choices = {"yes":True, "y":True, "ye":True,
			   "no":False, "n":False }

	if default == None:
		prompt = " [y/n] "
	elif default == True:
		prompt = " [Y/n] "
	elif default == False:
		prompt = " [y/N] "
	else:
		raise ValueError("invalid default answer: '%s'" % default)

	while 1:
		sys.stdout.write(question + prompt)
		choice = input().lower()
		if default is not None and choice == '':
			return default
		elif choice in choices.keys():
			return choices[choice]
		else:
			sys.stdout.write("Please respond with 'yes' or 'no' "\
							 "(or 'y' or 'n').\n")


def main(argv):
	state.current = state.LOADING_CONFIG

	init_config(argv)

	target = config['global']['target']

	migrated_re = re.compile(
			r'^Migrated to (%s)#(\d+) by \[.*\]' % target)

	# Determine if any of the found issues have already been migrated and mark
	# them if such.  Already migrated issues will be ignored unless the
	# update-existing option is set.

	def issue_was_migrated(issue):
		"""
		Determine if the issue looks like it has already been migrated by this
		script.

		If the issue was migrated, it returns an `Issue` object representing
		its migration destination; returns `False` otherwise.
		"""

		for line in issue['body'].splitlines():
			m = migrated_re.match(line)
			if m:
				return Issue(m.group(1), int(m.group(2)))

		return False

	state.current = state.FETCHING_ISSUES
	# Argparser will prevent us from getting both issue ids and specifying
	# issue state, so no duplicates will be added
	issues = []
	for repo in config['global']['sources']:
		issues_to_import = get_repository_option(repo, 'import-issues')

		if (len(issues_to_import) == 1 and
				issues_to_import[0] in ('all', 'open', 'closed')):
			issues += get_issues(repo, state=issues_to_import[0])
		elif len(issues_to_import) == 1 and issues_to_import[0] == 'migrated':
			for issue in get_issues(repo, state='all'):
				if issue_was_migrated(issue):
					issues.append(issue)
		else:
			issues += get_issues_by_id(repo, issues_to_import)

	# Sort issues from all repositories
	def sort_key(issue):
		# Sort chronologically first, then if there there is an overlap there
		# (the API only offers second-level resolution) sort also by issue
		# number so that issues created in the same second in the same
		# repository should still be inserted in the correct order)
		created = datetime.strptime(issue['created_at'], ISO_8601_UTC)
		return (created, issue['number'])

	issues.sort(key=sort_key)

	# Get all issues in the target repository; obviously if issues are created
	# in the target repo before the script is finished running this list will
	# be inaccurate; later we will warn the user to lock down the target (and
	# source) repos before merging in order to prevent this
	# TODO: I wonder if this lockdown could actually be done via the API?
	target_issues = get_issues(target, state='all')
	# Annoyingly, the GitHub API does not have a way to ask for a simple count
	# of issues; instead we have to download all the issues in full in order to
	# count them

	# Create a map from issues in the source repositories to the issues they
	# will become in the new repository
	new_issue_idx = len(target_issues) + 1
	issue_map = OrderedDict()

	# Skip all pull requests
	issues = [issue for issue in issues if 'pull_request' not in issue]

	for issue in issues:
		migrated = issue['migrated'] = issue_was_migrated(issue)
		old = Issue(issue['repository'], issue['number'])
		if migrated:
			new = migrated
		else:
			new = Issue(target, new_issue_idx)
			new_issue_idx += 1

		issue_map[old] = new

	# Further states defined within the function
	# Finally, add these issues to the target repository
	import_issues(issues, issue_map)

	state.current = state.COMPLETE


if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
