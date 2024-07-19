import sys
from pickle import dump, load
from math import floor, log, pow
from os import listdir, path, stat
from configparser import ConfigParser

# read config file
config = ConfigParser()
config.read('config.ini', encoding='utf-8')


class Scan:
    """
        Class Scan
    """

    @staticmethod
    def build_prefix_table(pattern: bytes) -> list:
        """
            The method to create prefix table

            Parameters:
                pattern (bytes): The pattern

            Return:
                The prefix table
        """

        prefix_table = [0] * len(pattern)
        length = 0
        i = 1

        while i < len(pattern):
            if pattern[i] == pattern[length]:
                length += 1
                prefix_table[i] = length
                i += 1

            else:
                if length != 0:
                    length = prefix_table[length - 1]

                else:
                    prefix_table[i] = 0
                    i += 1

        return prefix_table

    @staticmethod
    def search_pattern_in_binary_file(pattern: bytes, file_path: str) -> list:
        """
            The method to search a pattern in a file

            Parameters:
                pattern (bytes): The pattern
                file_path (str): The file path

            Return:
                The list matches
        """

        # open file
        with open(file_path, 'rb') as file:
            binary_data = file.read()

        prefix_table = Scan.build_prefix_table(pattern)
        pattern_length = len(pattern)
        text_length = len(binary_data)

        i = 0
        j = 0
        result = []

        while i < text_length:
            if pattern[j] == binary_data[i]:
                i += 1
                j += 1

                if j == pattern_length:
                    result.append(i - pattern_length)
                    j = prefix_table[j - 1]

            else:
                if j != 0:
                    j = prefix_table[j - 1]

                else:
                    i += 1

        return result

    @staticmethod
    def scan_file() -> None:
        """
            The method to scan files for any malware
        """

        print(f"***** Virus Scanner *****\n")
        print("Directory:", config['scan']['scanFileLoc'])

        # create list of previous patterns
        patterns = Scan.load_patterns()

        # search each pattern in each Benign files to remove false patterns
        files = listdir(config['scan']['scanFileLoc'])
        for file in files:
            write = sys.stdout.write
            write('\b' * 100)
            write(f'{files.index(file) + 1}/{len(files)}')

            for pattern in patterns:
                matches = Scan.search_pattern_in_binary_file(bytes(pattern), config['scan']['scanFileLoc'] + file)

                if matches:
                    print(f"\nFound a infected file: '{file}'")
                    break

        print("\nDone !")

    @staticmethod
    def save_patterns(data: list) -> None:
        """
            The method to save patterns list to database

            Parameters:
                data (list): The list of patterns
        """

        with open(config['scan']['database'], "wb") as f:
            dump(data, f)

    @staticmethod
    def load_patterns() -> list:
        """
            The method to load list of patterns to program

            Return:
                The list of patterns
        """

        data = []

        if path.getsize(config['scan']['database']) > 0:
            with open(config['scan']['database'], "rb") as f:
                data = load(f)

        return data


class Analyze:
    """
        Class Analyze
    """

    @staticmethod
    def lcs_bytes(a: bytes, b: bytes) -> bytearray:
        """
            The method to find the Longest Common Subsequence of two binary files

            Parameters:
                a (bytes): The first binary file content
                b (bytes): The second binary file content

            Return:
                The binary array of the longest common subsequence
        """

        m, n = len(a), len(b)

        # Create a 2D array to store the lengths of LCS
        lengths = [[0] * (n + 1) for _ in range(m + 1)]

        # Compute lengths of LCS
        for i in range(m):
            for j in range(n):
                if a[i] == b[j]:
                    lengths[i + 1][j + 1] = lengths[i][j] + 1

                else:
                    lengths[i + 1][j + 1] = max(lengths[i + 1][j], lengths[i][j + 1])

        # Construct the LCS from the lengths array
        lcs = bytearray()

        i, j = m, n
        while i > 0 and j > 0:
            if a[i - 1] == b[j - 1]:
                lcs.append(a[i - 1])
                i -= 1
                j -= 1

            elif lengths[i][j - 1] > lengths[i - 1][j]:
                j -= 1

            else:
                i -= 1

        # Reverse the LCS and return it
        lcs.reverse()

        return lcs

    @staticmethod
    def convert_size(size_bytes: int) -> str:
        """
            The method to calculate size of file by its bits

            Parameters:
                size_bytes (int): The file's size in bit

            Return:
                The string value of size
        """

        if size_bytes == 0:
            return "0B"

        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(floor(log(size_bytes, 1024)))
        p = pow(1024, i)
        s = round(size_bytes / p, 2)

        return "%s %s" % (s, size_name[i])

    @staticmethod
    def find_virus_patterns() -> None:
        """
            The method to find LCS of first file and other files of a directory,
        """

        print(f"***** Virus Pattern Finder *****\n")

        # create list of files and sort it by size
        files = [f"{config['analysis']['findPatternLoc']}/{i}" for i in listdir(config['analysis']['findPatternLoc'])]
        files = sorted(files, key=lambda x: stat(x).st_size)

        # load previous patterns
        patterns = Analyze.load_patterns()

        x, y = 0, 0

        while x < int(config['analysis']['accuracy']):  # just to compare files with accuracy first files
            y = x + 1

            # open first file
            with open(files[x], 'rb') as f:
                content_x = f.read()

            print(f"Compare file: '{files[x].split('/')[-1]}' [{Analyze.convert_size(stat(files[x]).st_size)}]")

            # open other files and use LCS
            while y < len(files) - 1:
                with open(files[y], 'rb') as f:
                    content_y = f.read()

                print(f"{y}) '{files[y].split('/')[-1]}' [{Analyze.convert_size(stat(files[y]).st_size)}]")

                # add pattern to list if it hasn't inserted yet
                temp = Analyze.lcs_bytes(content_x, content_y)
                if temp not in patterns: patterns.append(temp)

                # save patterns to database
                Analyze.save_patterns(patterns)
                y += 1

            print()
            x += 1

        print("Done !\n")

    @staticmethod
    def clean_virus_patterns() -> None:
        """
            The method to clean patterns from unwanted and wrong ones
        """

        print(f"***** Virus Pattern Cleaner *****\n")

        # create list of previous patterns
        patterns = Scan.load_patterns()
        cleaned = []

        # search each pattern in each Benign files to remove false patterns
        for pattern in patterns:
            write = sys.stdout.write
            write('\b' * 100)
            write(f'{patterns.index(pattern) + 1}/{len(patterns)}')

            for file in listdir(config['analysis']['testPatternLoc']):
                matches = Scan.search_pattern_in_binary_file(pattern, config['analysis']['testPatternLoc'] + file)

                if matches:
                    print(f"\nFound wrong pattern: pattern{patterns[patterns.index(pattern)]} in {file}")
                    break

                else:
                    cleaned.append(pattern)

        # save cleaned patterns to database
        Analyze.save_patterns(cleaned)

        print("\nDone !")

    @staticmethod
    def verify_virus_patterns() -> None:
        """
            The method to verify patterns with real malware files
        """

        print(f"***** Virus Pattern Verifier *****\n")

        # create list of previous patterns
        patterns = Scan.load_patterns()
        verified = []

        # search each pattern in each malware files to remove false patterns
        for pattern in patterns:
            write = sys.stdout.write
            write('\b' * 100)
            write(f'{patterns.index(pattern) + 1}/{len(patterns)}')

            for file in listdir(config['analysis']['testPatternLoc']):
                matches = Scan.search_pattern_in_binary_file(pattern, config['analysis']['testPatternLoc'] + file)

                if matches:
                    if pattern not in verified: verified.append(pattern)
                    break

        # save verified patterns to database
        Analyze.save_patterns(verified)

        print(f"\nDone ! {len(verified)} pattern(s) verified !")

    @staticmethod
    def dupl_virus_patterns() -> None:
        """
            The method to remove similar patterns and keep minimum of those
        """

        print(f"***** Virus Similarity Pattern Cleaner *****\n")

        # load patterns
        patterns = Scan.load_patterns()
        dup_index = []

        x, y = 0, 0
        while x < len(patterns):
            y = 0
            while y < len(patterns):
                prefix_table = Scan.build_prefix_table(patterns[x])
                pattern_length = len(patterns[x])
                text_length = len(patterns[y])

                i = 0
                j = 0
                result = []

                while i < text_length:
                    if patterns[x][j] == patterns[y][i]:
                        i += 1
                        j += 1

                        if j == pattern_length:
                            result.append(i - pattern_length)
                            j = prefix_table[j - 1]
                    else:
                        if j != 0:
                            j = prefix_table[j - 1]

                        else:
                            i += 1

                if result and x != y:
                    dup_index.append((x, y))

                y += 1

            write = sys.stdout.write
            write('\b' * 100)
            write(f'{x}/{len(patterns)}')

            x += 1

        print()

        for index in dup_index:
            minn = index[0] if len(patterns[index[0]]) < len(patterns[index[1]]) else index[1]
            patterns.remove(patterns[minn])

        Analyze.save_patterns(patterns)

        print("Done !")

    @staticmethod
    def save_patterns(data: list) -> None:
        """
            The method to save patterns list to database

            Parameters:
                data (list): The list of patterns
        """

        with open(config['analysis']['database'], "wb") as f:
            dump(data, f)

    @staticmethod
    def load_patterns() -> list:
        """
            The method to load list of patterns to program

            Return:
                The list of patterns
        """

        data = []

        if path.getsize(config['analysis']['database']) > 0:
            with open(config['analysis']['database'], "rb") as f:
                data = load(f)

        return data


if __name__ == '__main__':
    analysis = Analyze()
    scan = Scan()

    # phase 1
    analysis.find_virus_patterns()

    # phase 2
    analysis.dupl_virus_patterns()

    # phase 3
    analysis.clean_virus_patterns()

    # phase 4
    analysis.verify_virus_patterns()

    # phase 5
    scan.scan_file()