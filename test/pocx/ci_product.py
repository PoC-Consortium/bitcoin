#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Explicit product selection for independent CI; paired local use is retained."""

PRODUCTS = {'bitcoin': 'OFF', 'pocx': 'ON'}


def selected(environment):
    if 'CI_PRODUCT' not in environment:
        return tuple(PRODUCTS)
    product = environment['CI_PRODUCT']
    if product not in PRODUCTS:
        raise ValueError('CI_PRODUCT must be bitcoin or pocx (omit for local paired execution)')
    return (product,)


def validate_phases(phases):
    names = [row['consensus'] for row in phases]
    if names not in (['bitcoin'], ['pocx'], ['bitcoin', 'pocx']):
        raise ValueError('Expected one selected product or an ordered original/native local pair')
    return names


def require_configuration(options, environment):
    products = selected(environment)
    if options.get('ENABLE_POCX') not in {PRODUCTS[product] for product in products}:
        raise ValueError('Compiled ENABLE_POCX does not match CI_PRODUCT')
