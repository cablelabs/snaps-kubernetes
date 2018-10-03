# Copyright 2018 ARICENT HOLDINGS LUXEMBOURG SARL and Cable Television
# Laboratories, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from mock import Mock


class FileMock(Mock):
    def __init__(self, **kwargs):
        super(FileMock, self).__init__(**kwargs)
        self.counter = 0

    def write(self, str):
        pass

    def __iter__(self):
        return self

    def next(self):
        if self.counter == 0:
            self.counter += 1
            return 'foo'
        else:
            raise StopIteration
