import json
import sys
import re


audit_format = ''


def read(filename):
	f = open(filename, "r")
	audit_format = f.read()
	
	offset = 0
	idx1, idx2 = 0, 0
	while True:
		idx1, idx2 = opened_tag_indices(audit_format[offset:])
		
		print(audit_format[idx1:idx2])
		tag, parameter = get_valid_tag(audit_format[idx1:idx2])

		audit_format = audit_format[idx1+2:]

		if tag:
			break
		else:
			offset = offset + idx2

	print(f'{idx1=} {idx2=}')
	print('->', audit_format[:500])
	return audit_format


def get_valid_tag(tag_to_check):
	tag_list = ['check_type', 'if', 'condition', 'then', 'else', 'report', 'custom_item', 'item']
	# print(f'{tag_to_check=}')

	opened_tag = re.search('<[a-z_]+', tag_to_check)
	if opened_tag:
		begin, end = opened_tag.span()

		tag_name = tag_to_check[1 + begin: end]

		tag_w_parameter = re.search('<[a-z_\s]+[:|>]+"([^"]*)">', tag_to_check)
		parameter = None
		if tag_w_parameter:
			str_tag_to_check = tag_to_check[tag_w_parameter.span()[0]:tag_w_parameter.span()[1]]
			parameter = str_tag_to_check.split(':')[1][1:-2]

		# print(tag_name)

		if tag_name in tag_list:
			return (tag_name, parameter) if parameter else (tag_name, '')

	return None, None


def get_item_details(text):
	# print(f'{text=}')
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
				content = content[:the_note.span()[0]+1] + content[the_note.span()[1] + ending.span()[1]:]
		else:
			break
	print(content)
	return content


def build_json_content(content):
	content = remove_notes(content)

	properties = [" system ", " type ", " cmd ", " description ", " info ", " expect ", " reference ", " see_also ",

				  "file", "regex", " collection ", " fieldsSelector ", " query ", " expect ", " solution ", " severity "]

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


		# print('~~', content[0:idx_p_start], '~')
		if idx_p_start == 0:
			prop_data_to_add = content
		else:
			prop_data_to_add = content[0:idx_p_start]

		prop_data_to_add = prop_data_to_add[prop_data_to_add.find(':')+1:]

		if build:
			json_format = json_format + '"' + prop_to_add + '":"' + prop_data_to_add.replace('\\', '\\\\', ).replace('"', '\\"', ).replace('\n', '\\n') + '",'

		# print('~', content[idx_p_start:idx_p_end], '~')

		prop_to_add = content[idx_p_start:idx_p_end]
		# print(content[idx_p_end:])
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
			# print('NOT VALID', audit_format[offset + opened_idx_start:offset + opened_idx_end])
			break

		# print(f'->({opened_idx_start=}, {first_closed_idx_start=})')
		if opened_idx_start < first_closed_idx_start:
			# print('entered')
			opened_idx_begin, closed_idx_end, replace, new_json_format, replace_json = audit_to_json(offset + opened_idx_end)
			if replace_json and json_format:
				json_list.append(new_json_format)
			else:
				if replace_json:
					json_list.append(new_json_format)
					json_format = new_json_format

			if replace:
				audit_format = audit_format[:offset + opened_idx_end] + audit_format[offset + opened_idx_end + closed_idx_end:]

			if opened_idx_begin == -1 and closed_idx_end == -1:

				if json_format:
					escaped = '{"tag":"' + audit_format[offset + opened_idx_start:offset + opened_idx_end]\
						.replace('"', '\\"',).replace('\n', '\\n') + '"' + '}'
					json_child = json.loads(escaped)
					json_child['the_data'] = json_list
				else:
					item_tag, parameter = get_item_details(audit_format[offset + opened_idx_start:offset + first_closed_idx_end])
					content = audit_format[offset + opened_idx_end + 1:offset + first_closed_idx_start-1]

					json_content = build_json_content(content)
					# print(content)

					escaped = '{"item":"' + item_tag + '",' +\
						'"content":' + json_content + ',' +\
						'"parameter":"' + parameter + '"}'
					json_child = json.loads(escaped)
				# print(escaped)

				return opened_idx_start, first_closed_idx_end, True, json_child, True

			else:
				pass

		else:
			break

	# print('returning -1')
	return -1, -1, False, None, False


if __name__ == '__main__':
	audit_format = read('CIS_Ubuntu_20.04_LTS_v1.1.0_Workstation_L1.audit')
	json_format = audit_to_json(0)[3]
	# print(json_format)

	json_file = open("audit.json", "w")
	json_file.write(json.dumps(json_format))
	json_file.close()

