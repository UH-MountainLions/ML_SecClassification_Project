#!/usr/bin/env python
# -*- encode: utf-8 -*-
"""Entrypoint for ml_program.

ml_program
Full license in LICENSE.md

This module is the main entrypoint for running ml_program.

Typical usage example:
$> python -m report_generator
"""
import os
import argparse
import logging


logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


def main_cli() -> None:
    """Entrypoint for application.

    :return: N/A
    """
    # Setup Argparse
    parser = argparse.ArgumentParser(
        prog='ml_program',
        description='Trains ML from passed in training files'
    )
    parser.add_argument('--log',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        default='info',
                        help='Set logging level (debug, info, warning, error, critical)')
    parser.add_argument('-tf', '--training_file',
                        default=None,
                        dest="csv_file",
                        help='CSV file to process')
    args = parser.parse_args()

    # setup logging
    logger.setLevel(args.log.upper())
    # Create file handler for logging
    log_file = os.path.join(os.path.dirname(__file__),
                            'debug.log')
    if os.path.exists(log_file):
        os.remove(log_file)
    file_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__),
                                                    'debug.log')
                                       )
    file_handler.setLevel(logging.DEBUG)
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    # Build formatters
    file_format = logging.Formatter("%(asctime)s::%(name)s::%(pathname)s(%(lineno)s) - %(message)s")
    con_format = logging.Formatter("%(name)s::%(levelname)s - %(message)s")
    # Attach formatters
    file_handler.setFormatter(file_format)
    console_handler.setFormatter(con_format)
    # add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Run program
    if args.csv_file:
        # TODO setup easy CLI process
        print('Not currently implemented!')
    else:
        pass


if __name__ == '__main__':
    main_cli()
