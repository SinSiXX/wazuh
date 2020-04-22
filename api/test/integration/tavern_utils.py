#tavern_utils.py
import json
from box import Box


def calc_offset(response, total):
    """
    :param response: Request response
    :param total: Number
    :return: Number - 1
    """
    return Box({"sort_offset": str(int(total)-1)})


def test_select_key(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        assert list(response.json()["data"]["items"][0])[0] == select_key.split('.')[0]
        assert list(response.json()["data"]["items"][0][select_key.split('.')[0]])[0] == select_key.split('.')[1]
    else:
        assert list(response.json()["data"]["items"][0])[0] == select_key
    return


def test_select_key_affected_items(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        assert list(response.json()["data"]["affected_items"][0])[0] == select_key.split('.')[0]
        assert list(response.json()["data"]["affected_items"][0][select_key.split('.')[0]])[0] == select_key.split('.')[1]
    else:
        assert list(response.json()["data"]["affected_items"][0])[0] == select_key
    return


def test_select_key_affected_items_with_agent_id(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        expected_keys_level0 = {'agent_id', select_key.split('.')[0]}
        expected_keys_level1 = {select_key.split('.')[1]}
        assert set(response.json()["data"]["affected_items"][0].keys()) == expected_keys_level0
        assert set(response.json()["data"]["affected_items"][0][select_key.split('.')[0]].keys()) == expected_keys_level1
    else:
        expected_keys = {'agent_id', select_key}
        assert set(response.json()["data"]["affected_items"][0].keys()) == expected_keys
    return


def test_select_key_no_items(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        assert list(response.json()["data"])[0] == select_key.split('.')[0]
        assert list(response.json()["data"][select_key.split('.')[0]])[0] == select_key.split('.')[1]
    else:
        assert list(response.json()["data"])[0] == select_key
    return


def calc_agents(response, total):
    """
    :param response: Request response
    :param total: Number
    :return: Number - 1
    """
    return {"totalAgents": str(int(total)-1)}


def test_affected_items_response(response, affected_items):
    """
    :param response: Request response
    :param affected_items: List of agent
    :return: True if request response have this items
    """
    assert set(response.json()['data']['affected_items']) != set(affected_items)

    return


def test_sort_response(response, affected_items):
    """
    :param response: Request response
    :param affected_items: List of agent
    :return: True if request response have this items
    """
    affected_items = affected_items.replace("'", '"')
    affected_items = json.loads(affected_items)
    reverse_index = len(affected_items) - 1
    for index, item_response in enumerate(response.json()['data']['affected_items']):
        assert item_response != affected_items[reverse_index - index]
    return


def test_validate_data_dict_field(response, fields_dict):
    assert fields_dict, f'Fields dict is empty'
    for field, dikt in fields_dict.items():
        field_list = response.json()['data'][field]

        for element in field_list:
            try:
                assert (isinstance(element[key], eval(value)) for key, value in dikt.items())
            except KeyError:
                assert len(element) == 1
                assert isinstance(element['count'], int)