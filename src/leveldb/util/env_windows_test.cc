// Copyright (c) 2018 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "leveldb/env.h"

#include <chrono>
#include <thread>

#include "port/port.h"
#include "util/env_windows_test_helper.h"
#include "util/testharness.h"

namespace leveldb {

static const int kMMapLimit = 4;

class EnvWindowsTest {
 public:
  static void SetFileLimits(int mmap_limit) {
    EnvWindowsTestHelper::SetReadOnlyMMapLimit(mmap_limit);
  }

  EnvWindowsTest() : env_(Env::Default()) {}

  Env* env_;
};

TEST(EnvWindowsTest, TestOpenOnRead) {
  // Write some test data to a single file that will be opened |n| times.
  std::string test_dir;
  ASSERT_OK(env_->GetTestDirectory(&test_dir));
  std::string test_file = test_dir + "/open_on_read.txt";

  FILE* f = fopen(test_file.c_str(), "w");
  ASSERT_TRUE(f != nullptr);
  const char kFileData[] = "abcdefghijklmnopqrstuvwxyz";
  fputs(kFileData, f);
  fclose(f);

  // Open test file some number above the sum of the two limits to force
  // leveldb::WindowsEnv to switch from mapping the file into memory
  // to basic file reading.
  const int kNumFiles = kMMapLimit + 5;
  leveldb::RandomAccessFile* files[kNumFiles] = {0};
  for (int i = 0; i < kNumFiles; i++) {
    ASSERT_OK(env_->NewRandomAccessFile(test_file, &files[i]));
  }
  char scratch;
  Slice read_result;
  for (int i = 0; i < kNumFiles; i++) {
    ASSERT_OK(files[i]->Read(i, 1, &read_result, &scratch));
    ASSERT_EQ(kFileData[i], read_result[0]);
  }
  for (int i = 0; i < kNumFiles; i++) {
    delete files[i];
  }
  ASSERT_OK(env_->DeleteFile(test_file));
}

TEST(EnvWindowsTest, RenameAfterTransientReadLock) {
  std::string test_dir;
  ASSERT_OK(env_->GetTestDirectory(&test_dir));
  const std::string from = test_dir + "/rename_replacement.txt";
  const std::string to = test_dir + "/rename_replaced.txt";
  ASSERT_OK(WriteStringToFile(env_, "replacement", from));
  ASSERT_OK(WriteStringToFile(env_, "replaced", to));

  // A reader without FILE_SHARE_DELETE temporarily prevents ReplaceFileW from
  // removing the old file. The replacement must succeed once it closes.
  SequentialFile* reader;
  ASSERT_OK(env_->NewSequentialFile(to, &reader));
  std::thread close_reader([reader] {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    delete reader;
  });
  const Status rename = env_->RenameFile(from, to);
  close_reader.join();
  ASSERT_OK(rename);

  std::string contents;
  ASSERT_OK(ReadFileToString(env_, to, &contents));
  ASSERT_EQ(contents, "replacement");
  ASSERT_OK(env_->DeleteFile(to));
}

}  // namespace leveldb

int main(int argc, char** argv) {
  // All tests currently run with the same read-only file limits.
  leveldb::EnvWindowsTest::SetFileLimits(leveldb::kMMapLimit);
  return leveldb::test::RunAllTests();
}
