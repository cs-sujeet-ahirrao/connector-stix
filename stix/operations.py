"""
Copyright start
Copyright (C) 2008 - 2021 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""
import ast
import datetime
import json
import time
from os.path import join

import html2text
import requests
from connectors.cyops_utilities.builtins import create_file_from_string, extract_artifacts
from django.conf import settings
from stix2validator import validate_string
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

try:
    from integrations.crudhub import trigger_ingest_playbook, download_file_from_cyops
except:
    # ignore. lower FSR version
    pass

logger = get_logger('stix')


def _make_request(url, method, body=None):
    try:
        from cshmac.requests import HmacAuth
        bodyless_methods = ['head', 'get']
        if method.lower() in bodyless_methods:
            body = None
        if type(body) == str:
            try:
                body = ast.literal_eval(body)
            except Exception:
                pass
        url = settings.CRUD_HUB_URL + url
        logger.info('Starting request: {0} , {1}'.format(method, url))
        auth = HmacAuth(url, method, settings.APPLIANCE_PUBLIC_KEY, settings.APPLIANCE_PRIVATE_KEY, json.dumps(body))
        response = requests.request(method, url, auth=auth, json=body, verify=False)
        return response.content
    except Exception as err:
        logger.exception(str(err))


def get_output_schema(config, params, *args, **kwargs):
    mode = params.get('output_mode')
    if mode == 'Save to File':
        return ({
            "md5": "",
            "sha1": "",
            "sha256": "",
            "filename": "",
            "content_length": "",
            "content_type": ""
        })
    elif str(config.get('spec_version')) == "2.0":
        return ({
            "type": "",
            "id": "",
            "spec_version": "",
            "objects": [
                {
                    "type": "",
                    "id": "",
                    "created": "",
                    "modified": "",
                    "name": "",
                    "description": "",
                    "pattern": "",
                    "valid_from": "",
                    "revoked": "",
                    "labels": [

                    ],
                    "object_marking_refs": [

                    ]
                },
                {
                    "type": "",
                    "id": "",
                    "created": "",
                    "definition_type": "",
                    "definition": {
                        "tlp": ""
                    }
                }
            ]
        })
    else:
        return ({
            "type": "",
            "id": "",
            "objects": [
                {
                    "type": "",
                    "spec_version": "",
                    "id": "",
                    "created": "",
                    "modified": "",
                    "name": "",
                    "description": "",
                    "indicator_types": [

                    ],
                    "pattern": "",
                    "pattern_type": "",
                    "pattern_version": "",
                    "valid_from": "",
                    "revoked": "",
                    "object_marking_refs": [

                    ]
                },
                {
                    "type": "",
                    "spec_version": "",
                    "id": "",
                    "created": "",
                    "definition_type": "",
                    "name": "",
                    "definition": {
                        "tlp": ""
                    }
                }
            ]
        })


def get_datetime(_epoch):
    if _epoch:
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        return str(datetime.datetime.utcfromtimestamp(_epoch).strftime(pattern))
    else:
        None


def get_epoch(_date):
    pattern = '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in _date else '%Y-%m-%dT%H:%M:%SZ'
    return int(time.mktime(time.strptime(_date, pattern)))


def html_text(_html):
    if _html is not None and _html != '':
        h = html2text.HTML2Text()
        return h.handle(_html).replace('\n', '').replace('#', '').replace('*', '').replace('-', '')
    else:
        return 'No description available'


def max_age(params, ioc):
    if params.get("expiry") is not None and params.get("expiry") != '':
        return get_epoch(ioc["valid_from"]) + (params.get("expiry") * 86400)
    elif "valid_until" in ioc.keys():
        return get_epoch(ioc["valid_until"])
    else:
        return None


def tlp(TLP_AMBER, TLP_RED, TLP_WHITE, TLP_GREEN, params):
    if params.get('tlp') == 'Red':
        return TLP_RED
    if params.get('tlp') == 'Amber':
        return TLP_AMBER
    if params.get('tlp') == 'Green':
        return TLP_GREEN
    if params.get('tlp') == 'White':
        return TLP_WHITE


def stix_spec(ioc, _version, params):
    return {
        "type": "indicator",
        "spec_version": _version,
        "created": get_epoch(ioc["created"]),
        "modified": get_epoch(ioc["modified"]),
        "recordTags": ioc["indicator_types"] if "indicator_types" in ioc else ioc['labels'],
        "name": ioc["name"],
        "description": ioc["description"] if "description" in ioc else None,
        "pattern": ioc["pattern"],
        "valid_from": get_epoch(ioc["valid_from"]),
        "confidence": params.get("confidence") if params.get("confidence") is not None and params.get(
            "confidence") != '' else 0,
        "reputation": REPUTATION_MAP.get(params.get("reputation")) if params.get(
            'reputation') is not None and params.get("reputation") != '' else REPUTATION_MAP.get("Suspicious"),
        "tlp": TLP_MAP.get(params.get("tlp")) if params.get("tlp") is not None and params.get(
            "tlp") != '' else TLP_MAP.get("White"),
        "valid_until": max_age(params, ioc)
    }


def create_indicators(config, params, **kwargs):
    try:
        indicators = []
        indicator_list = params.get('indicator_list')
        if indicator_list:
            if str(config.get('spec_version')) == "2.1":
                from stix2.v21 import (Identity, MarkingDefinition, Indicator, Bundle, TLP_AMBER, TLP_RED, TLP_WHITE,
                                       TLP_GREEN)
                for ioc in indicator_list:
                    indicators.append(
                        Indicator(
                            type='indicator',
                            name=ioc['reputation']['itemValue'] + "-" + ioc['typeofindicator']['itemValue'],
                            description=html_text(ioc['description']),
                            indicator_types=[ioc['reputation']['itemValue']],
                            pattern='[' + INDICATOR_PARAM_MAP.get(ioc['typeofindicator']['itemValue']) + ' = \'' +
                                    ioc['value'] + '\']',
                            pattern_type='stix',
                            created=get_datetime(ioc['firstSeen']),
                            modified=get_datetime(ioc['lastSeen']),
                            object_marking_refs=tlp(TLP_AMBER, TLP_RED, TLP_WHITE, TLP_GREEN, params)
                        ))
                bundle = Bundle(*indicators, tlp(TLP_AMBER, TLP_RED, TLP_WHITE, TLP_GREEN, params))
            else:
                from stix2.v20 import (Identity, Indicator, MarkingDefinition, Bundle, TLP_AMBER, TLP_RED, TLP_GREEN,
                                       TLP_WHITE)
                for ioc in indicator_list:
                    indicators.append(
                        Indicator(
                            type='indicator',
                            name=ioc['reputation']['itemValue'] + "-" + ioc['typeofindicator']['itemValue'],
                            description=html_text(ioc['description']),
                            labels=[
                                ioc['reputation']['itemValue']
                            ],
                            pattern='[' + INDICATOR_PARAM_MAP.get(
                                ioc['typeofindicator']['itemValue']) + ' = \'' + ioc['value'] + '\']',
                            created=get_datetime(ioc['firstSeen']),
                            modified=get_datetime(ioc['lastSeen']),
                            object_marking_refs=tlp(TLP_AMBER, TLP_RED, TLP_WHITE, TLP_GREEN, params)
                        ))
                bundle = Bundle(*indicators, tlp(TLP_AMBER, TLP_RED, TLP_WHITE, TLP_GREEN, params))
            results = validate_string(str(bundle))
            if results.is_valid:
                if params.get('file_response'):
                    return create_file_from_string(contents=str(bundle), filename=params.get('filename'))
                else:
                    return bundle
            else:
                raise ConnectorError(results.errors[0])
        else:
            raise ConnectorError("Empty Indicator List")
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def extract_indicators(config, params, **kwargs):
    indicators = []
    mode = params.get('output_mode')
    try:
        logger.info("Starting upload_object function")
        file_id = params.get("file_id")
        spec_version = str(config.get("spec_version"))
        try:
            if 'api/3/' in file_id:
                from integrations.crudhub import download_file_from_cyops
                res = download_file_from_cyops(file_id)
                file_path = join('/tmp', res['cyops_file_path'])
            else:
                file_path = join('/tmp', file_id)
            with open(file_path) as attachment:
                json_data = attachment.read()
        except:
            json_data = _make_request(file_id, "get")
        data = json.loads(json_data)
        for ioc in data["objects"]:
            if ioc["type"] == "indicator" and "spec_version" in ioc.keys() and spec_version == "2.1":
                indicators.append(stix_spec(ioc, spec_version, params))
            elif ioc["type"] == "indicator" and "spec_version" not in ioc.keys() and spec_version == "2.0":
                indicators.append(stix_spec(ioc, spec_version, params))
        if len(indicators) > 0:
            if mode == 'Create as Feed Records in FortiSOAR':
                create_pb_id = params.get("create_pb_id")
                if '/' in create_pb_id:
                    create_pb_id = create_pb_id.split("/")[-1]
                trigger_ingest_playbook(indicators, create_pb_id, parent_env=kwargs.get('env', {}),
                                        batch_size=1000, dedup_field="pattern")
                return 'Successfully triggered playbooks to create feed records'
            seen = set()
            deduped_indicators = [x for x in indicators if
                                  [x["pattern"] not in seen, seen.add(x["pattern"])][0]]
            if mode == 'Save to File':
                return create_file_from_string(contents=deduped_indicators, filename=params.get('filename'))
            else:
                return deduped_indicators
        else:
            raise ConnectorError(
                "Either the Input file is empty or the specification version for its content is not supported")
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _check_health(config):
    try:
        if str(config.get('spec_version')) == "2.0" or str(config.get('spec_version')) == "2.1":
            logger.info("connector available")
            return True
        else:
            raise Exception("Not Valid STIX Specification version")
    except Exception as e:
        logger.error("Health check failed.")
        raise ConnectorError(e)


operations = {
    'extract_indicators': extract_indicators,
    'create_indicators': create_indicators,
    'get_output_schema': get_output_schema
}
