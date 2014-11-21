#!/usr/bin/env python3

import argparse
import base64
import configparser
import getpass
import json
import os
import urllib.request
import urllib.error
import urllib.parse
import sys

from collections import defaultdict, OrderedDict
from datetime import datetime
from string import Template


__location__ = os.path.realpath(os.path.join(os.getcwd(),
                                os.path.dirname(__file__)))
DEFAULT_CONFIG_FILE = os.path.join(__location__, 'config.ini')

config = defaultdict(dict)


ISO_8601_UTC = '%Y-%m-%dT%H:%M:%SZ'


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
    'ignore_comments': {'section': 'global', 'option': 'import-comments',
                        'negate': True},
    'ignore_milestone': {'section': 'global', 'option': 'import-milestone',
                         'negate': True},
    'ignore_labels': {'section': 'global', 'option': 'import-labels',
                      'negate': True},
    'import_issues': {'section': 'global', 'option': 'import-issues',
                      'multiple': True},
    'issue_template': {'section': 'format', 'option': 'issue-template'},
    'comment_template': {'section': 'format', 'option': 'comment-template'},
    'pull_request_template': {'section': 'format',
                              'option': 'comment-template'}
}


# Set of config option names that take boolean values; the options listed here
# can either be in the global section, or in per-repository sections
BOOLEAN_OPTS = set(['import-comments',  'import-milestone', 'import-labels'])


def init_config():
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

    arg_parser.add_argument('--ignore-comments', dest='ignore_comments',
            action='store_true', help="Do not import comments in the issue.")

    arg_parser.add_argument('--ignore-milestone', dest='ignore_milestone',
            action='store_true',
            help="Do not import the milestone attached to the issue.")

    arg_parser.add_argument('--ignore-labels', dest='ignore_labels',
            action='store_true',
            help="Do not import labels attached to the issue.")

    arg_parser.add_argument('--issue-template',
            help="Specify a template file for use with issues.")

    arg_parser.add_argument('--comment-template',
            help="Specify a template file for use with comments.")

    arg_parser.add_argument('--pull-request-template',
            help="Specify a template file for use with pull requests.")

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

    include_group.add_argument('-i', '--issues', dest='import_issues',
            type=int, nargs='+', help="The list of issues to import.");


    # First parse arguments that affect reading the config files; use this to
    # set various defaults and then parse the remaining options
    conf_args, _ = conf_parser.parse_known_args()

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

    args = arg_parser.parse_args()

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
                username = get_username(query, msg_2)

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


def send_request(repo, url, post_data=None):
    if post_data is not None:
        post_data = json.dumps(post_data).encode("utf-8")

    repo_url = get_repository_option(repo, 'url')
    full_url = "%s/%s" % (repo_url, url)
    req = urllib.request.Request(full_url, post_data)

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

        error_details = error.read();
        error_details = json.loads(error_details.decode("utf-8"))

        if error.code in HTTP_ERROR_MESSAGES:
            sys.exit(HTTP_ERROR_MESSAGES[error.code])
        else:
            error_message = ("ERROR: There was a problem importing the "
                             "issues.\n%s %s" % (error.code, error.reason))
            if 'message' in error_details:
                error_message += "\nDETAILS: " + error_details['message']
            sys.exit(error_message)

    return json.loads(json_data.decode("utf-8"))


def get_milestones(repo):
    """Get all open milestones for repository."""

    return send_request(repo, "milestones?state=open")


def get_labels(repo):
    """Get all labels for repository."""

    return send_request(repo, "labels")


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
    while True:
        query_args = {'direction': 'asc', 'page': page}
        if state in ('open', 'closed'):
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
        page += 1
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


def import_comments(comments, issue_number):
    result_comments = []
    for comment in comments:

        template_data = {}
        template_data['user_name'] = comment['user']['login']
        template_data['user_url'] = comment['user']['html_url']
        template_data['user_avatar'] = comment['user']['avatar_url']
        template_data['date'] = format_date(comment['created_at'])
        template_data['url'] =  comment['html_url']
        template_data['body'] = comment['body']

        comment['body'] = format_comment(template_data)

        target = config['global']['target']
        result_comment = send_request(target, "issues/%s/comments" %
                                      issue_number, comment)
        result_comments.append(result_comment)

    return result_comments


# Will only import milestones and issues that are in use by the imported
# issues, and do not exist in the target repository
def import_issues(issues, issue_map):
    state.current = state.GENERATING

    # TODO: get_milestones and get_labels could simply be modified to return
    # mappings keyed on the names in the first place; this would be more useful
    target = config['global']['target']
    known_milestones = get_milestones(target)
    def get_milestone_by_title(title):
        for milestone in known_milestones:
            if milestone['title'] == title:
                return milestone
        return None

    known_labels = get_labels(target)
    def get_label_by_name(name):
        for label in known_labels:
            if label['name'] == name:
                return label
        return None

    new_issues = []
    num_new_comments = 0
    new_milestones = []
    new_labels = []

    for issue in issues:
        new_issue = {}
        new_issue['title'] = issue['title']

        # Temporary fix for marking closed issues
        if issue['closed_at']:
            new_issue['title'] = "[CLOSED] " + new_issue['title']

        repo = issue['repository']

        import_comments = get_repository_option(repo, 'import-comments')
        if import_comments and issue.get('comments', 0) != 0:
            num_new_comments += int(issue['comments'])
            new_issue['comments'] = get_comments_on_issue('source', issue)

        import_milestone = get_repository_option(repo, 'import-milestone')
        if import_milestone and issue.get('milestone') is not None:
            # Since the milestones' ids are going to differ, we will compare
            # them by title instead
            milestone_title = issue['milestone']['title']
            found_milestone = get_milestone_by_title(milestone_title)
            if found_milestone:
                new_issue['milestone_object'] = found_milestone
            else:
                new_milestone = issue['milestone']
                new_issue['milestone_object'] = new_milestone
                # Allow it to be found next time
                known_milestones.append(new_milestone)
                # Put it in a queue to add it later
                new_milestones.append(new_milestone)

        import_labels = get_repository_option(repo, 'import-labels')
        if import_labels and issue.get('labels') is not None:
            new_issue['label_objects'] = []
            for issue_label in issue['labels']:
                found_label = get_label_by_name(issue_label['name'])
                if found_label:
                    new_issue['label_objects'].append(found_label)
                else:
                    new_issue['label_objects'].append(issue_label)
                    # Allow it to be found next time
                    known_labels.append(issue_label)
                    # Put it in a queue to add it later
                    new_labels.append(issue_label)

        template_data = {}
        template_data['user_name'] = issue['user']['login']
        template_data['user_url'] = issue['user']['html_url']
        template_data['user_avatar'] = issue['user']['avatar_url']
        template_data['date'] = format_date(issue['created_at'])
        template_data['url'] =  issue['html_url']
        template_data['body'] = issue['body']

        if ("pull_request" in issue and
                issue['pull_request']['html_url'] is not None):
            new_issue['body'] = format_pull_request(template_data)
        else:
            new_issue['body'] = format_issue(template_data)

        new_issues.append(new_issue)

    state.current = state.IMPORT_CONFIRMATION

    print("You are about to add to '%s':" % target)
    print(" *", len(new_issues), "new issues:")

    for old, new in issue_map.items():
        print("   *", old, "->", new)

    print(" *", num_new_comments, "new comments")
    print(" *", len(new_milestones), "new milestones")
    print(" *", len(new_labels), "new labels")
    if not yes_no("Are you sure you wish to continue?"):
        sys.exit()

    state.current = state.IMPORTING

    for milestone in new_milestones:
        result_milestone = import_milestone(milestone)
        milestone['number'] = result_milestone['number']
        milestone['url'] = result_milestone['url']

    for label in new_labels:
        result_label = import_label(label)

    result_issues = []
    for issue in new_issues:
        if 'milestone_object' in issue:
            issue['milestone'] = issue['milestone_object']['number']
            del issue['milestone_object']

        if 'label_objects' in issue:
            issue_labels = []
            for label in issue['label_objects']:
                issue_labels.append(label['name'])
            issue['labels'] = issue_labels
            del issue['label_objects']

        result_issue = send_request(target, "issues", issue)
        print("Successfully created issue '%s'" % result_issue['title'])

        if 'comments' in issue:
            result_comments = import_comments(issue['comments'],
                                              result_issue['number'])
            print(" > Successfully added", len(result_comments), "comments.")

        result_issues.append(result_issue)

    state.current = state.IMPORT_COMPLETE

    return result_issues


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


if __name__ == '__main__':

    state.current = state.LOADING_CONFIG

    init_config()

    state.current = state.FETCHING_ISSUES

    # Argparser will prevent us from getting both issue ids and specifying
    # issue state, so no duplicates will be added
    issues = []
    for repo in config['global']['sources']:
        issues_to_import = get_repository_option(repo, 'import-issues')

        if (len(issues_to_import) == 1 and
                issues_to_import[0] in ('all', 'open', 'closed')):
            issues += get_issues(repo, state=issues_to_import[0])
        else:
            issues += get_issues_by_id(repo, issues_to_import)

    # Sort issues from all repositories chronologically
    issues.sort(key=lambda i: datetime.strptime(i['created_at'],
                                                ISO_8601_UTC))

    # Get all issues in the target repository; obviously if issues are created
    # in the target repo before the script is finished running this list will
    # be inaccurate; later we will warn the user to lock down the target (and
    # source) repos before merging in order to prevent this
    # TODO: I wonder if this lockdown could actually be done via the API?
    target = config['global']['target']
    target_issues = get_issues(target)
    # Annoyingly, the GitHub API does not have a way to ask for a simple count
    # of issues; instead we have to download all the issues in full in order to
    # count them

    # Create a map from issues in the source repositories to the issues they
    # will become in the new repository
    issue_map = OrderedDict()
    for idx, issue in enumerate(issues):
        old = '%s#%s' % (issue['repository'], issue['number'])
        new = '%s#%s' % (target, len(target_issues) + idx + 1)
        issue_map[old] = new

    # Further states defined within the function
    # Finally, add these issues to the target repository
    import_issues(issues, issue_map)

    state.current = state.COMPLETE
