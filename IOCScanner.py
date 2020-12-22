import time
import yara
import os
import sys
import stat
import colorama
import datetime
import logging
import collections

# global Variables
verbose = 0


def load_rules(path=''):
    """Loading Yara Rules from given Path, if index.yar is found, ask User to use instead"""
    time_loading = time.perf_counter()
    print("Loading start")
    logging.info("Loading started at" + str(datetime.datetime.today()))
    siglist = {}
    if os.path.isdir(path):
        for dirpath, dirnames, filenames in os.walk(path):
            if 'index.yar' in filenames:
                ind = input("index.yar found; Do you want to use it? (y/N) ")
                if ind == 'y':
                    siglist = {}
                    sigkey = 'index.yar'
                    sigtup = {sigkey: os.path.join(dirpath, sigkey)}
                    siglist.update(sigtup)
                    break
            for name in filenames:
                sigpath = os.path.join(dirpath, name)
                sigkey = name
                sigtup = {sigkey: sigpath}
                siglist.update(sigtup)
            if '.git' in dirnames:
                dirnames.remove('.git')
            if '.github' in dirnames:
                dirnames.remove('.github')
    else:
        siglist = {}
        sigpath = path
        sigkey = os.path.basename(path)
        sigtup = {sigkey: sigpath}
        siglist.update(sigtup)
    time_loading2 = time.perf_counter()
    print(f"Loading completed in {time_loading2 - time_loading:0.4f} seconds")
    logging.info("Loading finished at" + str(datetime.datetime.today()))

    return siglist


def match_rules(dir_path, rules, timeout=100):
    """Matching function; creates Matcher objects for each file, keeps only the ones with matches"""
    time_matching = time.perf_counter()
    print("Matching start (Note: This will take some time, expect at least 1 hour)")
    logging.info("Matching started at" + str(datetime.datetime.today()))
    matches = []
    current = ''
    global verbose
    try:
        matches = []
        for dir, dirnames, filenames in os.walk(dir_path):
            level = dir.replace(dir_path, '').count(os.sep)
            dirindent = ' ' * 4 * level + '|---'
            if verbose > 0:
                print(colorama.Fore.WHITE + '{}{}/'.format(dirindent, os.path.basename(dir)))
            for filename in filenames:
                fileindent = ' ' * 4 * (level + 1) + '|---'
                if verbose > 1:
                    print(colorama.Fore.WHITE + '{}{}'.format(fileindent, filename))
                try:
                    if not stat.S_ISFIFO(os.stat(dir + "/" + filename).st_mode):
                        matcherobj = Matcher(rules, timeout)
                        if matcherobj.scan(dir + "/" + filename):
                            yield matcherobj
                    else:
                        logging.warning("Skipping FIFO Pipe: " + dir + "/" + filename)
                except yara.TimeoutError as err1:
                    logging.error("Yara Timeout while Scanning File@{}".format(err1))
                except FileNotFoundError as err2:
                    logging.error("File does not exist (probably broken link) @ {}".format(err2))
                except yara.Error as err3:
                    logging.error("Yara Error while Scanning File: {}".format(err3))
    except Exception:
        print(colorama.Fore.RED + "Unexpected Error:", sys.exc_info()[0])
        raise
    time_matching2 = time.perf_counter()
    logging.info("Matching finished at" + str(datetime.datetime.today()))
    print(f"Matching completed in {time_matching2 - time_matching:0.4f} seconds")


class Matcher(object):
    """Matcher class; is used to call yara.rules.match for given file path"""
    def __init__(self, rules, timeout):
        self._file_path = ""
        self._match = None
        self.rules = rules
        self.timeout = timeout

    def scan(self, file_path):
        self._file_path = file_path
        self._match = self.rules.match(file_path, timeout=self.timeout)
        return bool(self._match)

    @property
    def file_path(self):
        return self._file_path

    @property
    def match(self):
        return self._match


def writetofile(matches, path='', rulefiles=[]):
    """method to write results from scan to path; default = '/tmp/IOCScanner; returns path from created file"""
    if path == '':
        pathtofolder = '/tmp/IOCScanner/'
    else:
        pathtofolder = path
    if not os.path.exists(pathtofolder) and not os.path.isdir(pathtofolder):
        os.mkdir(pathtofolder)
    totalpath = pathtofolder + str(datetime.date.today())
    index = ""
    while os.path.exists(totalpath):
        if index:
            totalpath = totalpath + "(" + str((int(index[0]) + 1)) + ")"
        else:
            index = "1"
    f = open(totalpath, "a")
    if rulefiles:
        for r in rulefiles:
            f.write("#Scanning with file: " + r + "\n")
    for i in matches:
        for q in i.match:
            f.write(i.file_path + "; " + q.rule + ";")
            for x in range(len(q.tags)):
                f.write(q.tags[x] + ";")
            f.write("\n")
    f.close()
    return totalpath


class Analyzer(object):
    """Analyzer class to analyze a result file; extracts rule names and tags"""
    def __init__(self, resultfile, top):
        self.resultfile = resultfile
        self.top = top
        self.tags = {}
        self.untagged = False
        self.entries = []
        self.dictentries = {}
        self.pick()

    def pick(self):
        """splits given file in lists; saves entries, rules and tags"""
        with open(self.resultfile, 'r') as f:
            for line in f:
                if line.startswith("#"):
                    continue
                split_line = line.split(";")
                for s in split_line[2:]:
                    if s not in self.tags:
                        dicvals = [split_line[1]]
                        dictup = {s: dicvals}
                        self.tags.update(dictup)
                    else:
                        if not split_line[1] in self.tags.get(s):
                            dicvals = []
                            for rule in self.tags[s]:
                                dicvals.append(rule)
                            dicvals.append(split_line[1])
                            dictup = {s: dicvals}
                            del self.tags[s]
                            self.tags.update(dictup)
                    if s == "yellow":
                        self.entries.append(split_line[0])
                        if split_line[0] in self.dictentries:
                            self.dictentries[split_line[0]].append(split_line[1])
                        else:
                            self.dictentries[split_line[0]] = [split_line[1]]

    def showresult(self):
        """method to show the results stored in a Analyzer object"""
        if "\n" in self.tags:
            self.untagged = True
        if "red" in self.tags:
            print(colorama.Fore.RED + "IoCs marked red where found:")
            for rule in self.tags["red"]:
                print("- " + rule + "\n")
        else:
            if "yellow" in self.tags:
                print(colorama.Fore.YELLOW + "IoCs marked yellow where found")
                for rule in self.tags["yellow"]:
                    print("- " + rule)
            else:
                print(colorama.Fore.GREEN + "No IoCs marked red or yellow where found")
        if self.untagged:
            print(colorama.Fore.WHITE + "\nUncategorized Rules have been used for this scan\n")
        self.countedentries = collections.Counter(self.entries)
        topentries = self.countedentries.most_common(int(self.top))
        print("The {} Files with most yellow matches are:".format(self.top))
        for entry in topentries:
            print("  - {} : {} matches".format(entry[0], entry[1]))
            for r in self.dictentries[entry[0]]:
                print("     -> {}".format(r))
        print(colorama.Fore.WHITE + "\nOther tags, that have been found:")
        for key in self.tags.keys():
            if not key == "\n":
                print("\n  " + key + " in rules:")
                for rule in self.tags[key]:
                    print("    - " + rule)


def main(args):
    logging.basicConfig(filename="/var/log/IoCScanner/IoCScan.log", level=logging.INFO, filemode='w')
    logging.debug(str(datetime.datetime.today()) + ": New Process started with")
    logging.debug(args)
    if args.verbose is not None:
        global verbose
        verbose = args.verbose
    if not os.path.exists("/var/log/IoCScanner"):
        os.mkdir("/var/log/IoCScanner")
    if args.analyze:
        analyzerobj = Analyzer(args.analyze, args.top)
        analyzerobj.showresult()
    else:
        rules = load_rules(str(args.rules_path))
        compiled_rules = yara.compile(filepaths=rules)
        matches = match_rules(args.img_path, compiled_rules, args.timeout)
        if not matches:
            print("No Matches found")
        else:
            path = writetofile(matches, args.tempfile, rules)
            analyzerobj = Analyzer(path, args.top)
            analyzerobj.showresult()
            if not args.file:
                os.remove(args.tempfile)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Yara Matching Program for Malware Forensics; Run as root for '
                                                 'logging in /var/log/IoCScanner')
    parser.add_argument('-i', dest='img_path', help='Path to the mounted image')
    parser.add_argument('-r', dest='rules_path', help='Path to yara rules')
    parser.add_argument('-v', dest='verbose', help='Show more details', action='count')
    parser.add_argument('-f', dest='file', help='Write results to permanently to file', action='store_true')
    parser.add_argument('-t', dest='timeout', help='Time till timeout in sec', default=100)
    parser.add_argument('-d', dest='tempfile', help='Path to File for File save', default='')
    parser.add_argument('-a', dest='analyze', help='Analyse a given result file', default=None)
    parser.add_argument('-n', dest='top', help='Amount of shown top matches, Default = 3', type=int, default=3)

    args = parser.parse_args()

    main(args)
