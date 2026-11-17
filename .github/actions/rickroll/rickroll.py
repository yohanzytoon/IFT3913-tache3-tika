#!/usr/bin/env python3
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Rickroll the CI run when a Surefire report contains a failing JUnit test case.

Exit code is always 0: the job is already red because the test step failed,
and this action must neither hide nor replace that status.
"""

import glob
import os
import xml.etree.ElementTree as ET

ROLL = r"""
  _   _                                                         _
 | \ | | _____   _____ _ __    __ _  ___  _ __  _ __   __ _    (_)_   _____
 |  \| |/ _ \ \ / / _ \ '__|  / _` |/ _ \| '_ \| '_ \ / _` |   | \ \ / / _ \
 | |\  |  __/\ V /  __/ |    | (_| | (_) | | | | | | | (_| |   | |\ V /  __/
 |_| \_|\___| \_/ \___|_|     \__, |\___/|_| |_|_| |_|\__,_|   |_| \_/ \___|
                              |___/          you up, never gonna let you down...
"""


def failing_test_cases(pattern):
    """Return (reports read, ["Class.method", ...]) for failing or erroring test cases."""
    reports = sorted(glob.glob(pattern, recursive=True))
    failures = []
    for report in reports:
        try:
            root = ET.parse(report).getroot()
        except ET.ParseError:
            print(f"::warning::Unreadable Surefire report ignored: {report}")
            continue
        for case in root.iter("testcase"):
            if case.find("failure") is not None or case.find("error") is not None:
                failures.append(f"{case.get('classname', '?')}.{case.get('name', '?')}")
    return reports, failures


def write(path_variable, text):
    path = os.environ.get(path_variable)
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def main():
    pattern = os.environ.get("REPORTS_GLOB", "**/target/surefire-reports/TEST-*.xml")
    video = os.environ.get("VIDEO_URL", "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
    reports, failures = failing_test_cases(pattern)

    if not failures:
        # No failing test case: the failure comes from compilation, dependencies
        # or another tool. That is not a test failure, so nobody gets rickrolled.
        print(f"{len(reports)} Surefire report(s) read, no failing test case: no rickroll.")
        write("GITHUB_OUTPUT", "rickrolled=false\nfailed-tests=0\n")
        return

    print(ROLL)
    print(f"{len(failures)} failing test case(s):")
    for name in failures:
        print(f"  - {name}")
    print(f"Watch the explanation of your failure: {video}")
    print(f"::error title=Never gonna give you up::{len(failures)} test(s) failed. "
          f"You have been rickrolled: {video}")

    listing = "\n".join(f"- `{name}`" for name in failures)
    write("GITHUB_STEP_SUMMARY",
          "## 🎵 Never gonna give you up\n\n"
          f"**{len(failures)} test(s) failed.** "
          f"[Click here for the detailed failure analysis]({video})\n\n"
          f"{listing}\n\n"
          f"[![Rickroll](https://img.youtube.com/vi/dQw4w9WgXcQ/0.jpg)]({video})\n")
    write("GITHUB_OUTPUT", f"rickrolled=true\nfailed-tests={len(failures)}\n")


if __name__ == "__main__":
    main()
