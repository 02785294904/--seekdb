/**
 * Copyright (c) 2025 OceanBase.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define USING_LOG_PREFIX SQL_ENG
#include "ob_file_scan_utils.h"
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sql/resolver/ob_resolver_utils.h"

namespace oceanbase
{
using namespace common;
namespace sql
{

int ObFileScanUtils::resolve_and_check_path(
    const common::ObString &raw_path,
    const common::ObString &secure_file_priv,
    const bool skip_priv_check,
    char *buf,
    const int64_t buf_len,
    common::ObString &real_path)
{
  int ret = OB_SUCCESS;
  real_path.reset();
  if (OB_ISNULL(buf) || buf_len <= 0 || raw_path.empty()) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid file path", K(ret), K(raw_path), KP(buf), K(buf_len));
  } else if (raw_path.length() >= PATH_MAX) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("file path is too long", K(ret), "length", raw_path.length());
  } else {
    // realpath() resolves every symlink, so the boundary check below sees the
    // same path the kernel will open.
    char cstyle[PATH_MAX];
    char resolved[PATH_MAX];
    struct stat stat_result;
    MEMCPY(cstyle, raw_path.ptr(), raw_path.length());
    cstyle[raw_path.length()] = '\0';
    if (OB_ISNULL(::realpath(cstyle, resolved))) {
      ret = OB_FILE_NOT_EXIST;
      LOG_WARN("failed to resolve file path", K(ret), K(raw_path), "errno", errno);
    } else {
      const int64_t resolved_len = STRLEN(resolved);
      if (resolved_len >= buf_len) {
        ret = OB_SIZE_OVERFLOW;
        LOG_WARN("resolved path does not fit", K(ret), K(resolved_len), K(buf_len));
      } else if (!skip_priv_check
                 && OB_FAIL(ObResolverUtils::check_secure_path(
                        secure_file_priv, common::ObString(resolved_len, resolved)))) {
        LOG_WARN("path is not allowed by secure_file_priv", K(ret),
                 K(secure_file_priv), "resolved_path", resolved);
      } else if (0 != ::stat(resolved, &stat_result)) {
        ret = OB_FILE_NOT_EXIST;
        LOG_WARN("failed to stat file", K(ret), "resolved_path", resolved, "errno", errno);
      } else if (!S_ISREG(stat_result.st_mode)) {
        ret = OB_INVALID_ARGUMENT;
        LOG_USER_ERROR(OB_INVALID_ARGUMENT, "file sql input is not a regular file");
        LOG_WARN("not a regular file", K(ret), "resolved_path", resolved);
      } else {
        MEMCPY(buf, resolved, resolved_len);
        buf[resolved_len] = '\0';
        real_path.assign_ptr(buf, resolved_len);
      }
    }
  }
  return ret;
}

int ObFileScanUtils::check_file_count(const int64_t match_count)
{
  int ret = OB_SUCCESS;
  if (match_count > ObFileScanLimits::MAX_FILE_COUNT) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("too many files matched", K(ret), K(match_count),
             "limit", ObFileScanLimits::MAX_FILE_COUNT);
  }
  return ret;
}

int ObFileScanUtils::check_column_count(const int64_t column_count)
{
  int ret = OB_SUCCESS;
  if (column_count > ObFileScanLimits::MAX_COLUMN_COUNT) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("too many columns", K(ret), K(column_count),
             "limit", ObFileScanLimits::MAX_COLUMN_COUNT);
  }
  return ret;
}

ObFileInput::ObFileInput()
  : fd_(-1),
    file_path_(),
    buf_(NULL),
    path_buf_(NULL),
    buf_alloc_(0),
    data_len_(0),
    pos_(0),
    read_off_(0),
    size_(0),
    mtime_(0),
    dev_(0),
    ino_(0),
    eof_(false),
    alloc_(NULL)
{
}

ObFileInput::~ObFileInput()
{
  close();
}

int ObFileInput::open(common::ObIAllocator &alloc, const common::ObString &real_path)
{
  int ret = OB_SUCCESS;
  close();
  if (real_path.empty() || real_path.length() >= PATH_MAX) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid resolved path", K(ret), K(real_path));
  } else if (OB_ISNULL(buf_ = static_cast<char *>(alloc.alloc(ObFileScanLimits::READ_BUF_SIZE)))) {
    ret = OB_ALLOCATE_MEMORY_FAILED;
    LOG_WARN("failed to alloc read buffer", K(ret), K(ObFileScanLimits::READ_BUF_SIZE));
  } else if (OB_ISNULL(path_buf_ = static_cast<char *>(alloc.alloc(real_path.length() + 1)))) {
    ret = OB_ALLOCATE_MEMORY_FAILED;
    LOG_WARN("failed to alloc path buffer", K(ret), K(real_path.length()));
  } else {
    alloc_ = &alloc;
    buf_alloc_ = ObFileScanLimits::READ_BUF_SIZE;
    MEMCPY(path_buf_, real_path.ptr(), real_path.length());
    path_buf_[real_path.length()] = '\0';
    file_path_.assign_ptr(path_buf_, real_path.length());
    char cstyle[PATH_MAX];
    struct stat stat_result;
    MEMCPY(cstyle, real_path.ptr(), real_path.length());
    cstyle[real_path.length()] = '\0';
    int fd = ::open(cstyle, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
      ret = OB_FILE_NOT_EXIST;
      LOG_WARN("failed to open file", K(ret), K(file_path_), "errno", errno);
    } else if (0 != ::fstat(fd, &stat_result) || !S_ISREG(stat_result.st_mode)) {
      ret = OB_INVALID_ARGUMENT;
      LOG_WARN("not a regular file", K(ret), K(file_path_), "errno", errno);
      ::close(fd);
    } else {
      fd_ = fd;
      dev_ = stat_result.st_dev;
      ino_ = stat_result.st_ino;
      size_ = stat_result.st_size;
      mtime_ = stat_result.st_mtime;
    }
  }
  if (OB_FAIL(ret)) {
    close();
  }
  return ret;
}

void ObFileInput::close()
{
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  if (OB_NOT_NULL(alloc_)) {
    if (OB_NOT_NULL(buf_)) {
      alloc_->free(buf_);
    }
    if (OB_NOT_NULL(path_buf_)) {
      alloc_->free(path_buf_);
    }
    alloc_ = NULL;
  }
  buf_ = NULL;
  path_buf_ = NULL;
  file_path_.reset();
  buf_alloc_ = 0;
  data_len_ = 0;
  pos_ = 0;
  read_off_ = 0;
  size_ = 0;
  mtime_ = 0;
  dev_ = 0;
  ino_ = 0;
  eof_ = false;
}

int ObFileInput::fill()
{
  int ret = OB_SUCCESS;
  if (!is_opened()) {
    ret = OB_NOT_INIT;
    LOG_WARN("file input is not opened", K(ret));
  } else {
    const int64_t remain = data_len_ - pos_;
    if (remain > 0) {
      MEMMOVE(buf_, buf_ + pos_, remain);
    }
    data_len_ = remain;
    pos_ = 0;
    while (OB_SUCC(ret) && !eof_ && data_len_ < buf_alloc_) {
      const ssize_t n = ::read(fd_, buf_ + data_len_, buf_alloc_ - data_len_);
      if (n < 0) {
        if (EINTR == errno) {
          continue;
        }
        ret = OB_IO_ERROR;
        LOG_WARN("failed to read file", K(ret), K(file_path_), "errno", errno);
      } else if (0 == n) {
        eof_ = true;
      } else {
        data_len_ += n;
        read_off_ += n;
      }
    }
    if (OB_SUCC(ret) && 0 == data_len_) {
      ret = OB_ITER_END;
    }
  }
  return ret;
}

int ObFileInput::check_fingerprint() const
{
  int ret = OB_SUCCESS;
  struct stat stat_result;
  if (0 != ::fstat(fd_, &stat_result)) {
    ret = OB_IO_ERROR;
    LOG_WARN("failed to stat opened file", K(ret), K(file_path_), "errno", errno);
  } else if (stat_result.st_dev != dev_
             || stat_result.st_ino != ino_
             || stat_result.st_size != size_
             || stat_result.st_mtime != mtime_) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("file changed after it was opened", K(ret), K(file_path_),
             "old_size", size_, "new_size", stat_result.st_size);
  }
  return ret;
}

int ObFileInput::seek_begin()
{
  int ret = OB_SUCCESS;
  if (!is_opened()) {
    ret = OB_NOT_INIT;
    LOG_WARN("file input is not opened", K(ret));
  } else if (OB_FAIL(check_fingerprint())) {
    LOG_WARN("failed to rescan file", K(ret), K(file_path_));
  } else if (0 != ::lseek(fd_, 0, SEEK_SET)) {
    ret = OB_IO_ERROR;
    LOG_WARN("failed to rewind file", K(ret), K(file_path_), "errno", errno);
  } else {
    data_len_ = 0;
    pos_ = 0;
    read_off_ = 0;
    eof_ = false;
  }
  return ret;
}

} // end namespace sql
} // end namespace oceanbase
