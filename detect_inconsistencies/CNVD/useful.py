# from util import *
# from config import *
# import copy
# import re
# from bs4 import BeautifulSoup
# from cpe_name_dic import cpe_software_version_dict
# from investigate import *
# from extract_pair import crawl_content_from_link
# import logging
#
# logging.basicConfig(format='%(asctime)s: %(levelname)s: %(message)s')
# logging.root.setLevel(level=logging.INFO)
#
# # from selenium import webdriver
# #
# # driver = webdriver.PhantomJS()
#
# standard = 'nvd' # 'cve'
# loose = True
# debug_mode = False
#
# modify_set = set()
#
# # todo: intersect and union


'''
师姐给的useful.py，主要是为了探究不一致性的根源时，用下面这个函数找到有软件版本更新的NVD的记录
get_cpe_description_ref_last_change_date

'''



def is_two_elem_in_one_elem(two_version, one_version):
    # two_version: ('1.1.1.11', '<=', 'X', '<=', '1.2.1')
    # one_version: ('<', '1.4.0.13')
    number_1, two_symbol_1, _, two_symbol_2, number_2 = two_version
    one_symbol, one_number = one_version

    compare_result_1 = compare_single_version(number_2, one_number)
    compare_result_2 = compare_single_version(number_1, one_number)

    if [one_symbol, two_symbol_2, compare_result_1] in [['<', '<', '<'],
                                                        ['<', '<', '='],
                                                        ['<=', '<=', '<'],
                                                        ['<=', '<=', '='],
                                                        ['<', '<=', '<'],
                                                        ['<=', '<', '<'],
                                                        ['<=', '<', '='],
                                                        ]:
        return True
    elif [one_symbol, two_symbol_1, compare_result_2] in [['>', '>', '>'],
                                                        ['>', '>', '='],
                                                        ['>=', '>=', '>'],
                                                        ['>=', '>=', '='],
                                                        ['>', '>=', '>'],
                                                        ['>=', '>', '>'],
                                                        ['>=', '>', '='],
                                                        ]:
        return True
    return False










def judge_only_db_before_nvd(db_date_dict, db):
    if db_date_dict[0][0] == db and db_date_dict[1][0] == 'nvd_publish' and db_date_dict[2][0] == 'nvd_modify':
        return True
    return False


def judge_nvd_latest(db_date_dict):
    if db_date_dict[-1][0].startswith('nvd') and db_date_dict[-2][0].startswith('nvd'):
        return True
    return False


def judge_nvd_late_than_db(db_date_dict, db):
     db_idx = get_db_idx(db_date_dict, db)
     nvd_idx = get_nvd_idx(db_date_dict)
     if db_idx < nvd_idx:
         return True
     return False


def get_db_idx(db_date_dict, db):
    idx = 0
    for i in db_date_dict:
        if i[0] == db:
            return idx
        idx += 1


def get_nvd_idx(db_date_dict):
    idx = 0
    for i in db_date_dict:
        if i[0].startswith('nvd'):
            return idx
        idx += 1


def traverse_measure_version_dict_old(version_dict):
    cve_id_set = set(version_dict.keys())
    idx = 0
    total_idx = 0
    # total_cnt = 10000

    # cve_id_set = {'CVE-2011-0403', 'CVE-2011-0406'}
    # cve_id_set = {'CVE-2014-1978', 'CVE-2014-1222', 'CVE-2011-0403', 'CVE-2011-0406'}
    for cve_id in cve_id_set:
        print(total_idx, cve_id)
        # if total_idx == total_cnt:
        #     break
        if total_idx%100 == 0:
            logging.info('total_idx: ' + str(total_idx))
        # have_captures = judge_archive_contain_nvd_capture(cve_id)
        link = 'https://nvd.nist.gov/vuln/detail/' + cve_id
        raw_content = get_nvd_content(link)
        if raw_content is None:
            continue
        cpe_changed, anchor_loc1 = judge_nvd_version_change(raw_content)
        description_changed, anchor_loc2 = judge_cve_description_or_ref_change(raw_content, cve_id, 1)
        ref_changed, anchor_loc3 = judge_cve_description_or_ref_change(raw_content, cve_id, 2)

        if cpe_changed or description_changed or ref_changed:
            logging.info('\n')

        if cpe_changed:
            logging.info('cpe_changed: ' + str(anchor_loc1))
        if description_changed:
            logging.info('description_change: ' + str(anchor_loc2))
        if ref_changed:
            logging.info('ref_change: ' + str(anchor_loc3))

        if cpe_changed or description_changed or ref_changed:
            _, _, db_date_dict, db_keys = get_db_date(version_dict[cve_id], standard)
            version_dict_for_a_cve_id = measure_version_dict(cve_id, version_dict[cve_id])
            logging.info(idx)
            logging.info(cve_id + ' ' + link)
            logging.info(version_dict_for_a_cve_id)
            logging.info(db_date_dict)

            idx += 1
        total_idx += 1


def format_nvd_date(nvd_date):
    month, day, year = nvd_date.split()[0].split('/')
    date_dict = {'year': year, 'month': format_day(month), 'day': format_day(day)}
    return date_dict


def get_cpe_description_ref_last_change_date(cve_id, raw_content, idx, version_dict_for_a_cve_id):
    change_history_dict = dict()
    soup = BeautifulSoup(raw_content)
    for a in soup.findAll('div', {"class": "vuln-change-history-container"}):
        change_table_idx = -1

        for b in a.findAll('span'):
            type_or_date_name = b.get('data-testid')

            is_type = '-type' in type_or_date_name
            change_table_idx = type_or_date_name.split('-')[-1]
            if is_type:
                change_history_dict[change_table_idx] = {'analysis': b.text.lower()}
            else:
                change_history_dict[change_table_idx]['date'] = format_nvd_date(b.text.lower())
            # print(type_or_date_name, b.text)

        change_history_dict[change_table_idx]['event'] = []
        event = dict()
        for c in a.findAll('td'):
            item = c.get('data-testid').lower().split('-')[-1]
            if item == 'action':
                event = dict()
            event[item] = c.text.lower()
            # print(item, c.text)
            if item == 'new':
                change_history_dict[change_table_idx]['event'].append(event)
    remove_initial_analysis(change_history_dict)
    # remove_cpe_change_whose_version_not_change(change_history_dict)
    change_date_dict = {
        'cve_idx': idx,
        'cve_id': cve_id,
        'publish': get_nvd_date('', pub_date=True, crawl_result=raw_content),
        'cpe': [],
        'ref': [],
        'description': [],
        'cpe_ref_same_day': False
    }
    db_date_dict = enrich_change_date_dict(change_history_dict, change_date_dict, version_dict_for_a_cve_id)
    return change_date_dict, db_date_dict


def remove_cpe_change_whose_version_not_change(change_history_dict):
    for idx in change_history_dict:
        table = change_history_dict[idx]
        if 'event' not in table:
            continue
        all_event = table['event']
        new_all_event = []

        event_idx = -1
        for event in all_event:
            event_idx += 1
            if not event['type'].startswith('cpe'):
                continue
            version_old = extract_version_from_cpe(event['old'])
            version_new = extract_version_from_cpe(event['new'])
            if version_new and version_old and version_old != version_new:
                new_all_event.append(event)

        change_history_dict[idx]['event'] = new_all_event


def extract_version_from_cpe(cpe):
    return cpe.split(':')[5:]


def remove_initial_analysis(change_history_dict):
    initail_analysis_key = max(list(change_history_dict.keys()))
    if change_history_dict[initail_analysis_key]['analysis'].startswith('initial'):
        del change_history_dict[initail_analysis_key]


# def remove_initial_analysis(change_history_dict):
#     for key in change_history_dict.keys():
#         if change_history_dict[key]['analysis'].startswith('initial'):
#             del change_history_dict[key]
#             break


def enrich_change_date_dict(change_history_dict, change_date_dict, version_dict_for_a_cve_id):

    for table_idx in change_history_dict:

        # print(table_idx, len(change_history_dict[table_idx]['event']), change_history_dict[table_idx])
        event_list = change_history_dict[table_idx]['event']
        table_date = change_history_dict[table_idx]['date']

        for event_dict in event_list:
            # print(event_dict)
            if event_dict['type'] == 'cpe configuration':
                change_date_dict['cpe'].append(table_date)
            elif event_dict['type'] == 'reference' and event_dict['action'] == 'added':
                change_date_dict['ref'].append(table_date)
            elif event_dict['type'] == 'description' and event_dict['action'] == 'changed':
                change_date_dict['description'].append(table_date)

    if insersect_ref_date_cpe_date(change_date_dict['cpe'], change_date_dict['ref']):
        change_date_dict['cpe_ref_same_day'] = True

    db_date_dict = compute_and_add_case_idx(change_date_dict, version_dict_for_a_cve_id)
    return db_date_dict
    # for i in change_date_dict:
    #     print(i, change_date_dict[i])


def insersect_ref_date_cpe_date(cpe_date_dict_list, ref_date_dict_list):
    for cpe_date_dict in cpe_date_dict_list:
        for ref_date_dict in ref_date_dict_list:
            if is_date_dict_same(cpe_date_dict, ref_date_dict):
                return True
    return False


def is_date_dict_same(x, y):
    shared_items = {k: x[k] for k in x if k in y and x[k] == y[k]}
    if len(shared_items) == 3:
        return True
    return False


def convert_date_to_dict(date):
    year, month, day = date.split('-')
    date_dict = {'year': year, 'month': format_day(month), 'day': format_day(day)}
    return date_dict


def get_cpe_change_date(change_date_dict):
    key_dict = {'cve': 'description', 'nvd': 'cpe'}
    nvd_cpe_change_date = change_date_dict[key_dict[standard]]
    if nvd_cpe_change_date:
        nvd_cpe_change_date = nvd_cpe_change_date[0]
    return nvd_cpe_change_date


def compute_and_add_case_idx(change_date_dict, version_dict_for_a_cve_id):

    # case 1: nvd cpe change before reports, nvd no cpe change
    # case 2: reports before nvd cpe change, nvd no cpe change
    # case 3: reports before nvd cpe change, nvd with cpe change

    case_idx = -1

    _, _, db_date_dict, db_keys = get_db_date(version_dict_for_a_cve_id, standard, with_standard=False)
    nvd_cpe_change_date = get_cpe_change_date(change_date_dict)

    # print(11111, nvd_cpe_change_date)
    nvd_publish_date = change_date_dict['publish']

    if not db_date_dict:
        change_date_dict[standard + '_case_idx'] = case_idx
        return

    report_latest_publish_date = convert_date_to_dict(db_date_dict[-1][-1])

    if not nvd_cpe_change_date:
        nvd_cpe_change_date = nvd_publish_date
        compare_date_result = compare_date(report_latest_publish_date, nvd_cpe_change_date)
        if compare_date_result == '>':
            case_idx = 1
        else:
            case_idx = 2
    else:
        compare_date_result = compare_date(report_latest_publish_date, nvd_cpe_change_date)
        if compare_date_result == '<':
            case_idx = 3

    change_date_dict[standard + '_case_idx'] = case_idx
    return db_date_dict


def contains_keyword(s):
    keyword = ["'loose_match': [False, '']",
               "'loose_match': [True, 'under']",
               "'loose_match': [True, 'over']"]
    # if "'loose_match': [True, 'exact']" in s:
    #     return False
    for i in keyword:
        if i in s:
            return True
    return False


def update_case_cnt_dict(date_dict, case_cnt_dict):
    case_idx = date_dict[standard + '_case_idx']
    if case_idx == -1:
        return
    case_cnt_dict[case_idx] += 1


def traverse_measure_version_dict(version_dict):
    cve_id_set = set(version_dict.keys())
    idx = 0
    total_idx = 0
    case_cnt_dict = {1: 0, 2: 0, 3: 0}
    # total_cnt = 10000

    # cve_id_set = {'CVE-2011-0403', 'CVE-2011-0406'}
    # cve_id_set = {'CVE-2011-0403', 'CVE-2011-0406'}
    # cve_id_set = {'CVE-2014-1978', 'CVE-2014-1222', 'CVE-2011-0403', 'CVE-2011-0406'}
    for cve_id in cve_id_set:
        if cve_id != 'CVE-2018-7254':
            continue

        # if total_idx == total_cnt:
        #     break

        link = 'https://nvd.nist.gov/vuln/detail/' + cve_id
        raw_content = get_nvd_content(link)
        if raw_content is None:
            continue

        version_dict_for_a_cve_id = measure_version_dict(cve_id, version_dict[cve_id], ignore_both_nvd_cve=True)
        if not contains_keyword(str(version_dict_for_a_cve_id)):
            continue

        total_idx += 1

        if total_idx % 100 == 0:
            logging.info('total_idx: ' + str(total_idx))

        date_dict, db_date_dict = get_cpe_description_ref_last_change_date(cve_id, raw_content, total_idx, version_dict_for_a_cve_id)
        update_case_cnt_dict(date_dict, case_cnt_dict)

        logging.info(str(date_dict))
        logging.info(str(version_dict_for_a_cve_id))
        logging.info(str(db_date_dict))
        logging.info(str(case_cnt_dict))
        logging.info(str([case_cnt_dict[i]/total_idx for i in case_cnt_dict]) + '\n')


def get_all_idx_of_substr(substr, long_str):
    return [m.start() for m in re.finditer(substr, long_str)]


def judge_cpe_changed(anchor_loc, end_loc):
    for cpe_change_loc in anchor_loc:
        if cpe_change_loc < end_loc:
            return True
    return False


def get_nvd_content(link, full=False):
    # https://web.archive.org/web/*/https://nvd.nist.gov/vuln/detail/CVE-2011-0406
    crawl_content_from_link(link)
    crawl_result = crawl_content_from_link(link)
    if crawl_result is None:
        return False
    raw_content, clean_content = crawl_result
    if full:
        return crawl_result
    return raw_content


def judge_nvd_version_change(raw_content):
    anchor = 'CPE Configuration'
    anchor_loc = get_all_idx_of_substr(anchor, raw_content)
    end_loc = raw_content.find('Initial CVE Analysis')

    cpe_changed = judge_cpe_changed(anchor_loc, end_loc)
    return cpe_changed, len(anchor_loc)


    # driver.get(link)
    # try:
    #     p_element = driver.find_element_by_id(id_='wb-meta')
    #     # print(p_element.text)
    #     return True
    # except:
    #     return False


def judge_cve_description_or_ref_change(raw_content, cve_id, flg):
    # print(raw_content)
    # anchor = 'Description'
    # anchor = "-type'>Description</td>"
    # if flg == 2:
    #     anchor = "-type'>Reference</td>"

    anchor = '>Description</td>'
    if flg == 2:
        anchor = '>Reference</td>'

    anchor_loc = get_all_idx_of_substr(anchor, raw_content)
    # CVE Modified by MITRE
    end_loc = raw_content.find('CVE Modified by')
    if end_loc != -1:
        # get_modified_object(raw_content, end_loc, cve_id)
        description_changed = judge_description_changed(anchor_loc, end_loc)
        return description_changed, len(anchor_loc)
    return False, False


# def get_modified_object(raw_content, loc1, cve_id):
#     loc2 = raw_content[loc1:].find('</span>')
#     modify_title = raw_content[loc1:loc2].strip()
#     if modify_title != '' and modify_title not in modify_set:
#         modify_set.add(modify_title)
#         logging.info('************ modify_set changed by ' + cve_id + ': ' + modify_title + ' ******************')


def judge_description_changed(anchor_loc, end_loc):
    for cpe_change_loc in anchor_loc:
        if cpe_change_loc > end_loc:
            return True
    return False


# def judge_archive_contain_nvd_capture(cve_id):
#     # https://nvd.nist.gov/vuln/detail/CVE-2017-12818#VulnChangeHistorySection
#     link = "https://nvd.nist.gov/vuln/detail/" + cve_id
#     driver.get(link)
#     try:
#         p_element = driver.find_element_by_id(id_='wb-meta')
#         # print(p_element.text)
#         return True
#     except:
#         return False


def compare(a, b):
    idx = 0
    while True:
        if idx >= len(a) or idx >= len(b):
            break
        if a[idx] != b[idx]:
            print(idx)
            print('aaaa', a[idx:])
            print('bbbb', b[idx:])
            break
        idx += 1


def pppp():
    a = '''
     cpe:2.3:a:symantec:web_gateway:5.0:*:*:*:*:*:*:*
 cpe:2.3:a:symantec:web_gateway:5.0.1:*:*:*:*:*:*:*
 cpe:2.3:a:symantec:web_gateway:5.0.2:*:*:*:*:*:*:*
 cpe:2.3:a:symantec:web_gateway:5.0.3:*:*:*:*:*:*:*
 cpe:2.3:a:symantec:web_gateway:5.0.3.18:*:*:*:*:*:*:*
 cpe:2.3:a:symantec:web_gateway:5.1:*:*:*:*:*:*:*
 cpe:2.3:a:symantec:web_gateway:5.1.1:*:*:*:*:*:*:*
 cpe:2.3:a:symantec:web_gateway:5.2:*:*:*:*:*:*:*
 cpe:2.3:a:symantec:web_gateway:5.2.1:*:*:*:*:*:*:*'''

    l = []
    a = a.split('\n')
    for i in a:
        l.append(i[i.find('5'):i.find(':*')])
    l.sort()
    print(l)

if __name__ == '__main__':
    # version_dict_ = get_version_data(version_data_path, before_march_data_name)
    # traverse_measure_version_dict(version_dict_)
    pppp()



