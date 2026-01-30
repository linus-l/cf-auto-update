#!/usr/bin/env python3

"""Script that checks if Proximus has changed our dynamic IP address at home
and updates DNS records with Cloudflare for letocart.be accordingly. This
script only touches records in a specified zone that have "script" in their
comment fields. 

.env    Contains: 
            API_TOKEN:
                https://developers.cloudflare.com/fundamentals/api/\
                        get-started/create-token/
            ZONE_ID:
                https://developers.cloudflare.com/fundamentals/account/\
                        find-account-and-zone-ids/
"""

import logging
import requests
from dotenv import dotenv_values
import json
from typing import Iterator


logging.basicConfig(
        format="{asctime}:{levelname}:\t{message}", 
        style="{",           # otherwise `format=` is specified with %s()
        datefmt="%F %T",
        level=logging.INFO,
)


def get_host_ip(ipv6 : str = False) -> str | None:
    """Get the public IP address of the host.

    Args:
        ipv6 (bool, optional): If False (default), get IPv4 address.
            If True, get IPv6 address.

    Returns:
        IPv4 or IPv6 address string, or Null if the request fails.
    """
    # doc: https://ip6.me/docs/
    if ipv6: 
        response = requests.get("https://ip6.me/api/")
        # We verify the first part of `response` against `filter_str` in case
        # the API returns the wrong kind
        filter_str = "IPv6"
    else:
        response = requests.get("https://ip4.me/api/")
        filter_str = "IPv4"

    match response.content.decode().split(","):
        case [filter_str, addr, *args]:
            logging.debug(f"Host public IP is {addr} ({ipv6=})")
            return addr
        case _:
            logging.error(f"Could not get public ip address ({ipv6=})")
            return None


def _is_enabled_a_or_aaaa_record(record: dict[str, str]) -> bool:
    """Verify that `record` is A or AAAA and contains "script" as comment."""
    comment_words = record["comment"]
    if record["type"] in ["A", "AAAA"] :
        if "script" in record["comment"].lower():
            return True
    return False


def a_and_aaaa_records(zone_url: str, api_token: str) -> Iterator[dict[str, str]]:
    """Get A and AAAA records from Cloudflare.

    This function acts as an iterator, yielding the A and AAAA record whose
    comment field starts with "script". 

    Args: 
        zone_url (str): The Cloudflare URL for a specific zone.
        api_token (str): Cloudflare API token.

    Yields: 
        record (dict): a dictionary representing an A or AAAA record. 
    """
    r = requests.get(
            f"{zone_url}/dns_records", 
            headers = {"Authorization": f"Bearer {api_token}"},
    )
    data = json.loads(r.content)
    records = data.get("result")
    for record in records:
        if _is_enabled_a_or_aaaa_record(record):
            yield record


def update_record(
        zone_url: str, old_record: dict[str, str], new_addr: str
) -> dict[str, str]: 
    """Update a given record to contain `new_addr`."""
    new_record = old_record.copy()
    new_record["content"] = new_addr
    new_record_json = json.dumps(new_record)

    result = requests.patch(
            f"{zone_url}/dns_records/{record['id']}",
            new_record_json,
            headers = {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json"
            },
    )
    logging.debug(result)
    logging.debug(result.content)


if __name__ == "__main__": 
    env_filename = ".env"
    env = dotenv_values(env_filename)
    zone_id = env["ZONE_ID"]
    zone_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
    api_token = env.get("API_TOKEN")
    
    ipv4 = get_host_ip(ipv6=False)
    ipv6 = get_host_ip(ipv6=True)

    logging.debug(f"{ipv4=}")
    logging.debug(f"{ipv6=}")

    for record in a_and_aaaa_records(zone_url, api_token): 
        logging.debug(record)
        match record["type"]: 
            case "A": 
                if ipv4 == None: 
                    continue
                if ipv4 != record["content"]:
                    update_record(zone_url, record, ipv4)
            case "AAAA":
                if ipv6 == None: 
                    continue
                if ipv6 != record["content"]:
                    update_record(zone_url, record, ipv6)

