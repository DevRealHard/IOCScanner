import tkinter
from tkinter import filedialog, ttk


class Gui(object):
    """GUI class"""
    def __init__(self, master):
        self.tags = []
        self.master = master
        self.selectedrules = []
        self.listbox = tkinter.Listbox(self.master, selectmode=tkinter.MULTIPLE, selectbackground="Red",
                                       highlightcolor="Red")
        self.listbox.grid(column=0, row=0)
        self.btn = tkinter.Button(self.master, text="Select", command=self.select)
        self.btn.grid(column=0, row=1)
        self.selectedfiles = self.selectfiles()
        self.selectrules(self.selectedfiles)


    def selectfiles(self):
        """Method to open file dialog to select rule files"""
        _rulefiles = filedialog.askopenfilenames(parent=self.master, title='Select Yara Rule Files to be tagged')
        _selectedfiles = self.master.tk.splitlist(_rulefiles)
        return _selectedfiles

    def select(self):
        """called function after button is pressed"""
        _rules = []
        _selection = self.listbox.curselection()
        for i in _selection:
            _item = self.listbox.get(i)
            _rules.append(_item)
        self.selectedrules = _rules
        self.master.withdraw()
        toplevel = tkinter.Toplevel(self.master)
        tagger = Tagger(toplevel, self.selectedfiles, self.selectedrules)

    def selectrules(self, _files):
        """extracts rules from given files"""
        _rules = []
        for f in _files:
            file = open(f, 'r')
            for line in file:
                if line.startswith("rule"):
                    split_line = line.split()
                    _rules.append(split_line[1])
        for _rule in _rules:
            self.listbox.insert(tkinter.END, _rule)

class Tagger(object):
    """Tagger class (also GUI) to tag selected rules"""
    def __init__(self, master, selectedfiles, selectedrules):
        self.tags = []
        self.master = master
        self.selecttags()
        self.selectedfiles = selectedfiles
        self.selectedrules = selectedrules

    def selecttags(self):
        """extracts tags from given string"""
        tags = tkinter.StringVar()
        tkinter.Label(self.master, text="Please write tags, seperated by space").pack()
        tkinter.Entry(self.master, textvariable=tags).pack()
        tkinter.Button(self.master, text="Ok", command=lambda: self.disassembletags(tags.get())).pack()

    def tag(self, _file, rules):
        """tags rule in file with given tags"""
        _rules = []
        with open(_file, 'r') as f:
            lines = []
            for line in f:
                if line.startswith("rule"):
                    split_line = line.split()
                    for tag in self.tags:
                        if split_line[1] in rules:
                            if len(split_line)<3:
                                split_line.append(" :")
                            split_line.append(" " + tag)
                    lines.append(' '.join(split_line) + "\n")
                else:
                    lines.append(line)
        with open(_file, "w") as f:
            for line in lines:
                f.write(line)

    def disassembletags(self, tags):
        """extracts tags from user input string; gets called after OK Button"""
        _tags = tags.split()
        for _tag in _tags:
            self.tags.append(_tag)
        for file in self.selectedfiles:
            self.tag(file, self.selectedrules)
        self.master.quit()

def main(args):
    master = tkinter.Tk()
    gui = Gui(master)
    master.mainloop()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='rootpath', help='Path to file directory')

    parser.add_argument('-v', dest='verbose', help='Show more details', action='count')
    parser.add_argument('-f', dest='file', help='Write results to file', action='store_true')

    args = parser.parse_args()

    main(args)
