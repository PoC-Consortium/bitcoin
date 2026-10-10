#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Preserve the CI Boost randomization setting without inheriting test filters."""
import re

MAX_SEED = 2**32 - 1
SEED_MESSAGE = 'Test cases order is shuffled using seed: '


def random_seed(environment):
    value = environment.get('BOOST_TEST_RANDOM', '0')
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+', value):
        raise ValueError('BOOST_TEST_RANDOM must be an unsigned integer')
    seed = int(value)
    if seed > MAX_SEED:
        raise ValueError('BOOST_TEST_RANDOM exceeds the Boost unsigned seed range')
    return seed


def environment(source):
    """Remove inherited selectors/report overrides, preserving only randomization."""
    seed = random_seed(source)
    result = {key: value for key, value in source.items() if not key.startswith('BOOST_TEST_')}
    result['BOOST_TEST_RANDOM'] = str(seed)
    if seed:
        # Boost logs the chosen time-based seed at message level. Retain that
        # real output so requested randomization can be independently checked.
        result['BOOST_TEST_LOG_LEVEL'] = 'message'
    return result


def record(source, log):
    return {'random_seed': random_seed(source), 'observed_seeds': observed_seeds(log)}


def observed_seeds(log):
    matches = re.findall(re.escape(SEED_MESSAGE) + r'([0-9]+)(?=\s|\x1b\[|$)', log)
    if len(matches) != log.count(SEED_MESSAGE):
        raise ValueError('Malformed Boost randomization seed output')
    seeds = [int(value) for value in matches]
    if any(seed > MAX_SEED for seed in seeds):
        raise ValueError('Boost reported an invalid randomization seed')
    return seeds


def verify(log, recorded, processes):
    if type(processes) is not int or processes < 1:
        raise ValueError('Expected a positive Boost process count')
    if (not isinstance(recorded, dict) or set(recorded) != {'random_seed', 'observed_seeds'} or
            type(recorded['random_seed']) is not int or not 0 <= recorded['random_seed'] <= MAX_SEED or
            not isinstance(recorded['observed_seeds'], list) or
            any(type(seed) is not int for seed in recorded['observed_seeds'])):
        raise ValueError('Missing or invalid Boost runtime provenance')
    seed = recorded['random_seed']
    actual = observed_seeds(log)
    if actual != recorded['observed_seeds']:
        raise ValueError('Boost randomization evidence differs from the recorded seeds')
    if (seed == 0 and actual) or (seed != 0 and len(actual) != processes):
        raise ValueError('Missing or unexpected Boost randomization executions')
    if seed > 1 and any(value != seed for value in actual):
        raise ValueError('Boost did not execute with the requested fixed seed')
    return recorded
