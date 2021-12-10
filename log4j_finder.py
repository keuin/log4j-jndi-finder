import os
import zipfile
from operator import attrgetter
from typing import Iterator

keywords = [x.lower() for x in ['JndiLookup']]


class RemovableZipfile:

    def __init__(self, zf: zipfile.ZipFile):
        self.zf = zf

    def remove(self, member):
        """Remove a file from the archive. The archive must be open with mode 'a'"""

        if self.zf.mode != 'a':
            raise RuntimeError("remove() requires mode 'a'")
        if not self.zf.fp:
            raise ValueError(
                "Attempt to write to ZIP archive that was already closed")
        if getattr(self.zf, '_writing'):
            raise ValueError(
                "Can't write to ZIP archive while an open writing handle exists."
            )

        # Make sure we have an info object
        if isinstance(member, zipfile.ZipInfo):
            # 'member' is already an info object
            zinfo = member
        else:
            # get the info object
            zinfo = self.zf.getinfo(member)

        return self._remove_member(zinfo)

    def _remove_member(self, member):
        # get a sorted filelist by header offset, in case the dir order
        # doesn't match the actual entry order
        fp = self.zf.fp
        entry_offset = 0
        filelist = sorted(self.zf.filelist, key=attrgetter('header_offset'))
        for i in range(len(filelist)):
            info = filelist[i]
            # find the target member
            if info.header_offset < member.header_offset:
                continue

            # get the total size of the entry
            entry_size = None
            if i == len(filelist) - 1:
                entry_size = self.zf.start_dir - info.header_offset
            else:
                entry_size = filelist[i + 1].header_offset - info.header_offset

            # found the member, set the entry offset
            if member == info:
                entry_offset = entry_size
                continue

            # Move entry
            # read the actual entry data
            fp.seek(info.header_offset)
            entry_data = fp.read(entry_size)

            # update the header
            info.header_offset -= entry_offset

            # write the entry to the new position
            fp.seek(info.header_offset)
            fp.write(entry_data)
            fp.flush()

        # update state
        self.zf.start_dir -= entry_offset
        self.zf.filelist.remove(member)
        del self.zf.NameToInfo[member.filename]
        self.zf._didModify = True

        # seek to the start of the central dir
        fp.seek(self.zf.start_dir)


def find_log4j(path: str,
               ignore_case: bool = False,
               scan_only: bool = True,
               confirm_before_removing: bool = True) -> Iterator[str]:
    if os.path.isdir(path):
        # find all sub files recursively
        for root, dirs, files in os.walk(path):
            for file in files:
                fpath = os.path.join(root, file)
                for kw in keywords:
                    if kw in file:
                        yield fpath
                yield from find_log4j(fpath)
    else:
        # this is a single file, check if it is a .jar file and dig into
        if not path.endswith('.jar') or (ignore_case and path.lower().endswith('.jar')):
            return
        if not zipfile.is_zipfile(path):
            print(f'[WARN] Invalid ZIP magic of file `{path}`. Skip.')
            return
        is_vulnerable = False  # if the jar file is vulnerable
        with zipfile.ZipFile(path, 'r') as zf:
            for info in zf.infolist():
                for kw in keywords:
                    if kw in info.filename.lower():
                        is_vulnerable = True
                        yield f'{path}:{info.filename}'
        if is_vulnerable and not scan_only:
            # try to remove vulnerable files in this .jar file
            with zipfile.ZipFile(path, 'a') as zf:
                rz = RemovableZipfile(zf)
                for info in zf.infolist():
                    for kw in keywords:
                        if kw in info.filename.lower():
                            really_remove = False
                            if confirm_before_removing:
                                really_remove = input(f'Delete `{path}:{info.filename}`? (y/N)').strip().lower() == 'y'
                            else:
                                really_remove = True

                            if really_remove:
                                print(f'[INFO] Removing {info.filename}')
                                rz.remove(info)
                            else:
                                print('Skip this file.')
                            break


if __name__ == '__main__':
    scan_only = input('Scan only? (Y/n)').strip().lower() != 'n'
    if scan_only:
        confirm_before_removing = True  # this doesn't matter
    else:
        confirm_before_removing = input('Confirm before removing? (Y/n)').strip().lower() != 'n'
    for s in find_log4j(input('Where to search (path to a directory, or path to a `.jar` file):'), scan_only=scan_only,
                        confirm_before_removing=confirm_before_removing):
        print(f'[ALERT] {s}')
