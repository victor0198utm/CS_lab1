import json
import re
import tkinter as tk
from tkinter import ttk, filedialog
import uuid
import sqlite3
from sqlite3 import Error


step_1 = ''
path = ''
audit_format = ''


def read(filename):
    f = open(filename, "r")
    audit_format = f.read()

    offset = 0
    idx1, idx2 = 0, 0
    while True:
        idx1, idx2 = opened_tag_indices(audit_format[offset:])

        tag, parameter = get_valid_tag(audit_format[idx1:idx2])

        audit_format = audit_format[idx1 + 2:]

        if tag:
            break
        else:
            offset = offset + idx2

    return audit_format


def get_valid_tag(tag_to_check):
    tag_list = ['check_type', 'if', 'condition', 'then', 'else', 'report', 'custom_item', 'item']

    opened_tag = re.search('<[a-z_]+', tag_to_check)
    if opened_tag:
        begin, end = opened_tag.span()

        tag_name = tag_to_check[1 + begin: end]

        tag_w_parameter = re.search('<[a-z_\s]+[:|>]+"([^"]*)">', tag_to_check)
        parameter = None
        if tag_w_parameter:
            str_tag_to_check = tag_to_check[tag_w_parameter.span()[0]:tag_w_parameter.span()[1]]
            parameter = str_tag_to_check.split(':')[1][1:-2]

        if tag_name in tag_list:
            return (tag_name, parameter) if parameter else (tag_name, '')

    return None, None


def get_item_details(text):
    tag, parameter = get_valid_tag(text)

    return tag, parameter


def opened_tag_indices(text):
    opened = re.search('<[a-z_\s]+>', text)
    opened_param = re.search('<[a-z_\s]+[:|>]+"([^"]*)">', text)

    if opened and opened_param:
        opened_idx_start = min(opened.span()[0], opened_param.span()[0])
        opened_idx_end = min(opened.span()[1], opened_param.span()[1])
    else:
        if opened:
            opened_idx_start = opened.span()[0]
            opened_idx_end = opened.span()[1]
        elif opened_param:
            opened_idx_start = opened_param.span()[0]
            opened_idx_end = opened_param.span()[1]
        else:
            return None, None

    return opened_idx_start, opened_idx_end


def check_valid_prop(content, idx):
    found_space, found_new_line = False, False
    while idx > 0:
        if not found_new_line and content[idx] == ' ':
            found_space = True
        elif found_space and content[idx] == '\n':
            found_new_line = True
            break
        else:
            return False

        idx = idx - 1
    return (idx == 0 and found_space) or (found_space and found_new_line)


def remove_notes(content):
    while True:
        the_note = re.search('\\n# Note:', content)
        if the_note:
            ending = re.search('\\n', content[the_note.span()[1]:])
            if ending:
                content = content[:the_note.span()[0] + 1] + content[the_note.span()[1] + ending.span()[1]:]
        else:
            break

    return content


def build_json_content(content):
    content = remove_notes(content)

    properties = [" name ", " system ", " type ", " cmd ", " description ", " info ", " expect ", " reference ",
                  " see_also ", " file ", " regex ", " collection ", " fieldsSelector ", " query ", " expect ",
                  " solution ", " severity ", " owner ", " mask ", " group "]
    json_format = '{'
    prop_to_add = ''
    prop_data_to_add = ''
    build = False
    while len(content) > 0:
        idx_p_start = 0
        idx_p_end = len(content)
        for prop in properties:
            prop_idxes = re.search(prop, content)
            if prop_idxes:
                prop_start, prop_end = prop_idxes.span()
            else:
                continue

            if idx_p_end > prop_end:
                if check_valid_prop(content, prop_start):
                    idx_p_start = prop_start
                    idx_p_end = prop_end

        if idx_p_start == 0:
            prop_data_to_add = content
        else:
            prop_data_to_add = content[0:idx_p_start]

        prop_data_to_add = prop_data_to_add[prop_data_to_add.find(':') + 1:]

        if build:
            json_format = json_format + '"' + prop_to_add + '":"' + prop_data_to_add.replace('\\', '\\\\', ).replace(
                '"', '\\"', ).replace('\n', '\\n') + '",'

        prop_to_add = content[idx_p_start:idx_p_end]
        content = content[idx_p_end:]

        build = True

    json_format = json_format[:-1] + '}'

    return json_format


def audit_to_json(offset):
    # REGEXES:
    # opened tags -> '<[a-z_\s]+>'
    #
    # opened tags with parameters -> '<[a-z_\s]+[:|>]+"([^"]*)">'
    #
    # closed tags -> '</[a-z_]*>'

    skip = ['user', 'username', 'password', 'package_name', 'service_name', 'protocol', 'port']

    global audit_format
    json_format = None
    json_child = None
    json_list = list()

    while True:

        first_closed = re.search('</[a-z_]*>', audit_format[offset:])
        if not first_closed:
            print('-> .audit parsing error: can not find closed tag')
            exit()

        first_closed_idx_start, first_closed_idx_end = first_closed.span()

        opened_idx_start, opened_idx_end = opened_tag_indices(audit_format[offset:])

        if not opened_idx_start and not opened_idx_end:
            break

        tag_name, parameter = get_valid_tag(audit_format[offset + opened_idx_start:offset + opened_idx_end])
        if not tag_name:
            break

        if opened_idx_start < first_closed_idx_start:
            opened_idx_begin, closed_idx_end, replace, new_json_format, replace_json = audit_to_json(
                offset + opened_idx_end)
            if replace_json and json_format:
                json_list.append(new_json_format)
            else:
                if replace_json:
                    json_list.append(new_json_format)
                    json_format = new_json_format

            if replace:
                audit_format = audit_format[:offset + opened_idx_end] + audit_format[
                                                                        offset + opened_idx_end + closed_idx_end:]

            if opened_idx_begin == -1 and closed_idx_end == -1:

                if json_format:
                    item_tag, parameter = get_item_details(
                        audit_format[offset + opened_idx_start:offset + opened_idx_end])
                    escaped = '{"tag":"' + item_tag + '"}'
                    json_child = json.loads(escaped)
                    if parameter:
                        json_child['parameter'] = parameter
                    json_child['data'] = json_list
                else:
                    item_tag, parameter = get_item_details(
                        audit_format[offset + opened_idx_start:offset + first_closed_idx_end])
                    content = audit_format[offset + opened_idx_end + 1:offset + first_closed_idx_start - 1]

                    json_content = build_json_content(content)
                    # print("~2~", json_content)

                    escaped = '{"item":"' + item_tag + '"}'
                    json_child = json.loads(escaped)

                    if parameter:
                        json_child['parameter'] = parameter
                    json_child['content'] = json.loads(json_content)
                return opened_idx_start, first_closed_idx_end, True, json_child, True

            else:
                pass

        else:
            break

    return -1, -1, False, None, False


class Application(tk.Tk):
    _filename = 'Select an .audit file'
    _file_path = None
    _treeview = None
    _conn = None
    _insert_cursor = None
    _json_data = None
    _cursor = None

    def __init__(self):
        super().__init__()
        self.title('Audit manager')
        self.geometry('1200x600')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.createWidgets()
        self.step_2()

    def step_2(self):
        global step_1
        global audit_format
        global path
        if step_1 == 'open' and path:
            audit_format = read(path)
            json_data = audit_to_json(0)[3]
            self._json_data = json_data

    def select_file(self):
        filetypes = (
            ('text files', '*.audit'),
            ('All files', '*.*')
        )

        self._file_path = filedialog.askopenfilename(
            title='Open a file',
            initialdir='/',
            filetypes=filetypes)

        self.set_filename(self._file_path)
        print(self._file_path)

        global audit_format
        audit_format = read(self._file_path)
        json_data = audit_to_json(0)[3]

        self.wirte_to_db(json_data)

        self.json_tree('', json_data)

        self._json_data = json_data

    def create_connection(self, db_file):
        conn = None
        try:
            conn = sqlite3.connect(db_file)
        except Error as e:
            print(e)

        return conn

    def tables_in_sqlite_db(self):
        cursor = self._conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [
            v[0] for v in cursor.fetchall()
            if v[0] != "sqlite_sequence"
        ]
        cursor.close()
        return tables

    def build_database(self):
        tables = self.tables_in_sqlite_db()

        cursor = self._conn.cursor()
        if not 'audits' in tables:
            cursor.execute('create table audits (id integer primary key autoincrement, title, first_id,  FOREIGN KEY(first_id) REFERENCES instructions(id))')
        if not 'instructions' in tables:
            cursor.execute("create table instructions (id, parent, keys, datas)")

    def load_file_to_db(self, parent, dictionary):
        for key in dictionary:
            uid = uuid.uuid4()
            if isinstance(dictionary[key], dict):
                self._cursor.execute("insert into instructions values (?, ?, ?, ?)", (str(uid), str(parent), key, None))
                self.load_file_to_db(uid, dictionary[key])
            elif isinstance(dictionary[key], list):
                self._cursor.execute("insert into instructions values (?, ?, ?, ?)", (str(uid), str(parent), key, None))
                self.load_file_to_db(uid,
                               dict([(i, x) for i, x in enumerate(dictionary[key])]))
            else:
                value = dictionary[key]
                if value is None:
                    value = 'None'
                self._cursor.execute("insert into instructions values (?, ?, ?, ?)", (str(uid), str(parent), key, value))

    def wirte_to_db(self, json_data):

        self._conn = self.create_connection('audits_sqlite3.db')

        self.build_database()

        self._cursor = self._conn.cursor()

        self._cursor.execute(f"SELECT * FROM audits WHERE audits.title like '{self._filename}'")

        rows = self._cursor.fetchall()

        if not rows:
            first_uid = uuid.uuid4()
            self._cursor.execute("insert into audits(first_id, title) values (?, ?)", (str(first_uid), self._filename))
            self.load_file_to_db(first_uid, json_data)

        self._cursor.close()

        self._conn.commit()
        self._conn.close()

    def set_filename(self, file_path):
        self._filename = str(file_path.split('/')[-1:][0]).replace(".audit", "")
        print(self._filename)
        self._treeview.heading('#0', text=self._filename, anchor='w')
        self._treeview.heading('Values', text='Values')

    def json_tree(self, parent, dictionary):
        for key in dictionary:
            uid = uuid.uuid4()
            if isinstance(dictionary[key], dict):
                self._treeview.insert(parent, 'end', uid, text=key)
                self.json_tree(uid, dictionary[key])
                self._treeview.item(parent, open=True)
            elif isinstance(dictionary[key], list):
                self._treeview.insert(parent, 'end', uid, text=key + '[]')
                self.json_tree(uid,
                               dict([(i, x) for i, x in enumerate(dictionary[key])]))
                self._treeview.item(parent, open=True)
            else:
                value = dictionary[key]
                if value is None:
                    value = 'None'

                if key in ['tag', 'parameter', 'item']:
                    self._treeview.insert(parent, 'end', uid, text=value)
                else:
                    self._treeview.insert(parent, 'end', uid, text=key, value=value)

    def run_selected(self):
        Run(self._json_data, self._filename)

    def run_all(self):
        pass

    def export_audit(self):
        pass

    def export_json(self):
        pass

    def createWidgets(self):
        menubar = tk.Menu(self)

        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open", command=self.select_file)
        filemenu.add_command(label="Exit", command=self.exit)
        menubar.add_cascade(label="File", menu=filemenu)

        run_menu = tk.Menu(menubar, tearoff=0)
        run_menu.add_command(label="Run selected", command=self.run_selected)
        run_menu.add_command(label="Run all", command=self.run_all)
        menubar.add_cascade(label="Run", menu=run_menu)

        export_menu = tk.Menu(menubar, tearoff=0)
        export_menu.add_command(label="As audit", command=self.export_audit)
        export_menu.add_command(label="As JSON", command=self.export_json)
        menubar.add_cascade(label="Export", menu=export_menu)

        self.config(menu=menubar)

        # Setup the Frames
        tree_frame = ttk.Frame(self, padding="3")
        tree_frame.grid(row=0, column=0, sticky=tk.NSEW)

        # Setup the Tree
        self._treeview = ttk.Treeview(tree_frame, columns='Values')
        self._treeview.heading('#0', text='Open an .audit file..', anchor='w')
        self._treeview.column('Values', width=700)
        self._treeview.pack(fill=tk.BOTH, expand=1)

    def exit(self):
        self.destroy()


class Start(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title('Audit manager')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.createWidgets()
        self.position_window()

    def position_window(self):
        w = 300  # width for the Tk root
        h = 100  # height for the Tk root
        ws = self.winfo_screenwidth()  # width of the screen
        hs = self.winfo_screenheight()  # height of the screen
        x = (ws / 2) - (w / 2)
        y = (hs / 2) - (h / 2) - 100

        self.geometry('%dx%d+%d+%d' % (w, h, x, y))

    def select_file(self):
        filetypes = (
            ('text files', '*.audit'),
            ('All files', '*.*')
        )

        global path
        path = filedialog.askopenfilename(
            title='Open a file',
            initialdir='/',
            filetypes=filetypes)

        global step_1
        step_1 = 'open'

        self.destroy()

    def recent(self):
        global step_1
        step_1 = 'recent'

        self.destroy()

    def createWidgets(self):
        button_continue = ttk.Button(self, text="Open recent project", command=self.recent)
        button_continue.place(x=140, y=20)
        button_open = ttk.Button(self, text="Open audit file", command=self.select_file)
        button_open.place(x=140, y=60)


class Run(tk.Tk):

    _json_data = None
    _list_data = list()
    _list_data_selected = list()
    _modify = None
    _filename = None

    def __init__(self, json_data, filename):
        super().__init__()
        self.withdraw()
        self._json_data = json_data
        self._filename = filename

        if self._json_data:
            self.title('Run audit')
            self.rowconfigure(0, weight=1)
            self.columnconfigure(1, weight=1)
            self.createWidgets()
            self.position_window()
            self.deiconify()

        else:
            tk.messagebox.showinfo('Warning', 'There is no audit opened in this session.')
            self.destroy()

    def position_window(self):
        w = 1230  # width for the Tk root
        h = 650  # height for the Tk root
        ws = self.winfo_screenwidth()  # width of the screen
        hs = self.winfo_screenheight()  # height of the screen
        x = (ws / 2) - (w / 2)
        y = (hs / 2) - (h / 2) - 100

        self.geometry('%dx%d+%d+%d' % (w, h, x, y))

    def createWidgets(self):

        the_frame = ttk.Frame(self, padding="3")
        the_frame.grid(row=0, column=0, rowspan=2)

        entry = ttk.Entry(the_frame)
        self._entry = entry
        entry.pack(side='top', expand='yes', fill='x')

        entry.bind("<KeyRelease>", self.find_item)
        self._entry.focus_set()

        scrollbar = tk.Scrollbar(the_frame, orient="vertical")
        scrollbar2 = tk.Scrollbar(the_frame, orient="horizontal")
        lb = tk.Listbox(the_frame, width=80, height=45, yscrollcommand=scrollbar.set, xscrollcommand=scrollbar2.set)
        lb.bind('<<ListboxSelect>>', self.onselect)
        self._lb = lb
        scrollbar.config(command=lb.yview)
        scrollbar.pack(side="right", fill="y")
        scrollbar2.config(command=lb.xview)
        scrollbar2.pack(side="bottom", fill="x")
        lb.pack(side='top', expand='yes', fill='both')

        self.load_items(lb, self._json_data)

        action_frame = tk.LabelFrame(self, text="Item details:", padx=10, pady=10)
        action_frame.grid(row=0, column=1, sticky='NW')

        label1 = tk.Label(action_frame, text='description', relief='flat', padx=5, pady=5)
        label1.grid(row=0, column=0, sticky='w')
        label2 = tk.Label(action_frame, text='info', relief='flat', padx=5, pady=5)
        label2.grid(row=1, column=0, sticky='w')
        label3 = tk.Label(action_frame, text='solution', relief='flat', padx=5, pady=5)
        label3.grid(row=2, column=0, sticky='w')
        label4 = tk.Label(action_frame, text='cmd', relief='flat', padx=5, pady=5)
        label4.grid(row=3, column=0, sticky='w')
        label5 = tk.Label(action_frame, text='file', relief='flat', padx=5, pady=5)
        label5.grid(row=4, column=0, sticky='w')
        label6 = tk.Label(action_frame, text='regex', relief='flat', padx=5, pady=5)
        label6.grid(row=5, column=0, sticky='w')
        label7 = tk.Label(action_frame, text='expect', relief='flat', padx=5, pady=5)
        label7.grid(row=6, column=0, sticky='w')

        entry1 = tk.Entry(action_frame, width=75)
        entry1.grid(row=0, column=1, sticky='w')
        entry2 = tk.Entry(action_frame, width=75)
        entry2.grid(row=1, column=1, sticky='w')
        entry3 = tk.Entry(action_frame, width=75)
        entry3.grid(row=2, column=1, sticky='w')
        entry4 = tk.Entry(action_frame, width=75)
        entry4.grid(row=3, column=1, sticky='w')
        entry5 = tk.Entry(action_frame, width=75)
        entry5.grid(row=4, column=1, sticky='w')
        entry6 = tk.Entry(action_frame, width=75)
        entry6.grid(row=5, column=1, sticky='w')
        entry7 = tk.Entry(action_frame, width=75)
        entry7.grid(row=6, column=1, sticky='w')

        self._description = entry1
        self._info = entry2
        self._solution = entry3
        self._cmd = entry4
        self._file = entry5
        self._regex = entry6
        self._expect = entry7

        selected_frame = ttk.Frame(self, padding="3")
        selected_frame.grid(row=1, column=1)

        btn_add = tk.Button(selected_frame, text="Add item", command=self.add_selected_item)
        btn_add.grid(row=0, column=0)
        btn_add = tk.Button(selected_frame, text="Remove item", command=self.remove_selected_item)
        btn_add.grid(row=0, column=1)
        btn_add = tk.Button(selected_frame, text="Add all items", command=self.add_all_items)
        btn_add.grid(row=0, column=2)
        btn_add = tk.Button(selected_frame, text="Remove all items", command=self.remove_all_items)
        btn_add.grid(row=0, column=3)

        frame_list = tk.Frame(selected_frame)
        frame_list.grid(row=1, columnspan=5)

        scrollbar_s = tk.Scrollbar(frame_list, orient="vertical")
        scrollbar_s_2 = tk.Scrollbar(frame_list, orient="horizontal")
        lb_selected = tk.Listbox(frame_list, width=83, height=25, yscrollcommand=scrollbar_s.set, xscrollcommand=scrollbar_s_2.set)
        lb_selected.bind('<<ListboxSelect>>', self.onselect)
        scrollbar_s.config(command=lb_selected.yview)
        scrollbar_s.pack(side="right", fill="y")
        scrollbar_s_2.config(command=lb_selected.xview)
        scrollbar_s_2.pack(side="bottom", fill="x")
        lb_selected.pack(side='top', expand='yes', fill='both')

        btn_add = tk.Button(frame_list, text="Run", command=self.add_selected_item)
        btn_add.pack(side='bottom', expand='yes', fill='both')

        self._lb_selected = lb_selected

    def add_selected_item(self):
        if not self._description.get() in self._list_data_selected:
            self._list_data_selected.append(self._description.get())
            self._lb_selected.insert('end', self._description.get())
        print(self._list_data_selected)

    def remove_selected_item(self):
        self._lb_selected.delete(0, 'end')
        tmp_list = list(self._list_data_selected)
        
        self._list_data_selected = list()
        print(f'{tmp_list=}')
        print(f'{self._description.get()=}')
        for item in tmp_list:
            if item != self._description.get():
                self._lb_selected.insert('end', item)
                self._list_data_selected.append(item)
        print(self._list_data_selected)

    def remove_all_items(self):
        self._lb_selected.delete(0, 'end')
        self._list_data_selected = list()
        print(self._list_data_selected)

    def add_all_items(self):
        self._lb_selected.delete(0, 'end')
        for tup in self._list_data:
            self._list_data_selected.append(tup[1])
            self._lb_selected.insert('end', tup[1])
        print(self._list_data_selected)

    def find_item(self, event):
        search_string = self._entry.get()
        print(search_string)
        self._lb.delete(0, 'end')

        for tup in self._list_data:
            result_obj = tup[1].find(search_string)
            if result_obj >= 0:
                self._lb.insert('end', tup[1])

    def onselect(self, evt):
        w = evt.widget
        if w.curselection():
            index = int(w.curselection()[0])
            value = w.get(index)
            for tup in self._list_data:
                if tup[1].find(value) == 0:
                    self.search_full_item(self._json_data, tup[0])

    def search_full_item(self, dictionary, search_description):
        for key in dictionary:
            if isinstance(dictionary[key], dict):
                if key == 'content':
                    self.select_item(dictionary[key], search_description)

                self.search_full_item(dictionary[key], search_description)

            elif isinstance(dictionary[key], list):

                self.search_full_item(dict([(i, x) for i, x in enumerate(dictionary[key])]), search_description)
            else:
                if dictionary[key] in ['condition', 'report']:
                    break

    def select_item(self, dictionary, search_description):
        item = None

        if ' description ' in dictionary.keys():
            if dictionary[' description '].find(search_description) == 0:
                print(dictionary)
                item = dictionary

        properties = [" name ", " system ", " type ", " cmd ", " description ", " info ", " expect ", " reference ",
                      " see_also ", " file ", " regex ", " collection ", " fieldsSelector ", " query ", " expect ",
                      " solution ", " severity ", " owner ", " mask ", " group "]
        if item:
            for prop in properties:
                if prop in item.keys():
                    print(prop, item[prop])
                    self._description.delete(0,"end")
                    self._description.insert(0, item[" description "][1:].replace('\n', '').replace('\"',''))
                    self._info.delete(0,"end")
                    self._info.insert(0, item[" info "][1:].replace('\n', '').replace('\"',''))
                    self._solution.delete(0,"end")
                    self._solution.insert(0, item[" solution "][1:].replace('\n', '').replace('\"',''))

                    self._cmd.delete(0,"end")
                    if " cmd " in item.keys():
                        self._cmd.insert(0, item[" cmd "][1:].replace('\n', '').replace('\"',''))

                    self._file.delete(0, "end")
                    if " file " in item.keys():
                        self._file.insert(0, item[" file "][1:].replace('\n', '').replace('\"', ''))

                    self._regex.delete(0, "end")
                    if " regex " in item.keys():
                        self._regex.insert(0, item[" regex "][1:].replace('\n', '').replace('\"', ''))

                    self._expect.delete(0,"end")
                    self._expect.insert(0, item[" expect "][1:].replace('\n', '').replace('\"',''))

    def load_items(self, lb, dictionary):
        for key in dictionary:
            if isinstance(dictionary[key], dict):
                if key == 'content':
                    print(dictionary[key])
                    self.add_item(lb, dictionary[key])

                self.load_items(lb, dictionary[key])

            elif isinstance(dictionary[key], list):
                # print('list')
                self.load_items(lb, dict([(i, x) for i, x in enumerate(dictionary[key])]))
            else:
                if dictionary[key] in ['condition', 'report']:
                    break

    def add_item(self, lb, dictionary):
        print(dictionary.keys())
        if ' description ' in dictionary.keys():
            show_string = dictionary[' description '][2:].replace('\n', '').replace('\"','')
            self._list_data.append((dictionary[' description '], show_string))
            lb.insert('end', show_string)

    def save_file(self):
        f = filedialog.asksaveasfile(initialfile='Untitled.txt', defaultextension=".txt", filetypes=[("All Files", "*.*"), ("Text Documents", "*.txt")])


if __name__ == '__main__':
    step_1 = 'open'

    if step_1 == 'open':
        app = Application()
        app.mainloop()

    elif step_1 == 'recent':
        pass
