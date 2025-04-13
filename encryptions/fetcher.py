# hCaptcha AES encryption key fetcher for n data
# I won't be releasing key fetchers for other keys 
# fuck dort he's a unskilled bitch


import base64
import os
import re
import subprocess
import requests


class HCaptchaKey:
    def __init__(self, version: str):
        self.version = version
        self.key = None
        
        self.ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.LCG_MULTIPLIER = 6364136223846793005
        self.MEMORY_OFFSET = 1075552

        self._wasm_binary = None
        self._wat_code = None
        self._c_code = None
        self._memory = []
        self._functions = {}
        self.key_factors = {}

    def run(self):
        self._extract_wasm()
        self._decompile_wasm()
        self._parse_wasm()
        self.key_factors = self._fetch_factors()
        self._generate_n_key()
        return self.key

    def _extract_wasm(self):
        hsw = requests.get(
            f"https://newassets.hcaptcha.com/c/{self.version}/hsw.js"
        ).text
        self._wasm_binary = base64.b64decode(hsw.split('0,null,"')[1].split('"')[0])
        print(f"extracted wasm binary: {len(self._wasm_binary)} bytes")

    def _decompile_wasm(self):
        with open("hsw.wasm", "wb") as f:
            f.write(self._wasm_binary)

        try:
            self._wat_code = self._run_tool("wasm2wat", "hsw.wasm")
            self._c_code = self._run_tool("wasm-decompile", "hsw.wasm")
        finally:
            os.unlink("hsw.wasm")

    def _run_tool(self, tool: str, input_path: str):
        result = subprocess.run(
            [tool, input_path], capture_output=True, text=True, check=True
        )
        return result.stdout

    def _parse_wasm(self):
        #  (data (;1;) (i32.const 1075552) "\01\00\00\00\00\00\00\009w...t\caF\02\b9\14\e0M")
        pattern = r"\(data\s*\(;1;\)\s*\(i32\.const\s*1075552\)\s*\"([^\"]+)\"\)"
        match = re.search(pattern, self._wat_code)

        raw_memory = match.group(1)
        memory_data = []
        i = 0
        length = len(raw_memory)

        while i < length:
            char = raw_memory[i]

            if char == '\\' and i + 2 < length:
                hex_pair = raw_memory[i + 1:i + 3]
                if re.match(r'[0-9A-Fa-f]{2}', hex_pair):
                    memory_data.append(int(hex_pair, 16))
                    i += 3
                else:
                    memory_data.append(ord(char))
                    i += 1
            else:
                memory_data.append(ord(char))
                i += 1

        self._memory = memory_data


        print(f"extracted memory: {len(self._memory)} bytes")
        lines = self._c_code.splitlines()
        i = ""

        for line in lines:
            if (
                any(
                    line.startswith(prefix)
                    for prefix in ["function", "export function"]
                )
                and "{" in line
            ):
                i = line
                ii = []
            elif line == "}" and ii:
                content = "\n".join(ii)
                if content.count("8589934624L") == 1:
                    self._functions[i] = content
                ii = []
                i = ""
            elif i:
                ii.append(line)

    def _fetch_factors(self):
        for function, body in dict(self._functions).items():
            if not function.startswith("function"):
                continue
            del self._functions[function]
            result = {}
            lines = body.split("\n")

            for i in range(len(lines) - 5):
                line1 = lines[i].strip()
                if not any(c + "b(" in line1 for c in self.ALPHABET):
                    continue
                if ", 0)" not in line1 and ", 0);" not in line1:
                    continue
                parts = line1.split(",")
                if len(parts) < 2:
                    continue
                key_seed_str = parts[-2].strip()
                if not key_seed_str.isdigit():
                    continue
                key_seed = int(key_seed_str)
                line2 = lines[i + 1].strip() if i + 1 < len(lines) else ""
                line3 = lines[i + 2].strip() if i + 2 < len(lines) else ""
                if not any(c + "b(" in line2 for c in self.ALPHABET):
                    continue
                if "8589934624L" not in line3 or not any(
                    c + "b(" in line3 for c in self.ALPHABET
                ):
                    continue

                for j in range(i + 3, min(i + 10, len(lines))):
                    line = lines[j].strip()
                    if "=" in line and "L" in line and "seed" not in result:
                        parts = line.split("=")
                        if len(parts) >= 2 and parts[0].strip().isalpha():
                            value_part = parts[1].strip()
                            if "L" in value_part:
                                value_part = value_part.split("L")[0].strip()
                                if value_part.lstrip("-").isdigit():
                                    result["seed"] = int(value_part)
                    elif "=" in line and "L" not in line and "memory" not in result:
                        parts = line.split("=")
                        if len(parts) >= 2 and parts[0].strip().isalpha():
                            digits = "".join(c for c in parts[1].strip() if c.isdigit())
                            if digits.isdigit():
                                result["memory"] = int(digits)
                    if "seed" in result and "memory" in result:
                        result["key_seed"] = key_seed
                        break

            for i in range(len(lines) - 6):
                line1, line2 = lines[i].strip(), lines[i + 1].strip()
                if not line1.startswith("label B_"):
                    continue
                if "6364136223846793005L" not in line2:
                    continue
                operator = "+" if "+" in line2.split("6364136223846793005L")[1] else "-"
                if operator not in ["+", "-"]:
                    continue
                parts = line2.split(operator)
                if len(parts) < 2:
                    continue
                factor_part = parts[1].strip()
                if "L" not in factor_part:
                    continue
                factor_str = factor_part.split("L")[0].strip()
                if not factor_str.isdigit():
                    continue
                key_factor1 = int(factor_str)
                line3, line4 = lines[i + 2].strip(), lines[i + 3].strip()
                line5, line6 = lines[i + 4].strip(), lines[i + 5].strip()
                line7 = lines[i + 6].strip() if i + 6 < len(lines) else ""
                if not all(
                    [
                        any(c + "b(" in line3 for c in self.ALPHABET),
                        any(c + "b(" in line4 for c in self.ALPHABET),
                        "=" in line5,
                        "select_if(" in line6,
                        line7.startswith("continue L_"),
                    ]
                ):
                    continue
                result["key_factor1"] = key_factor1
                result["operator"] = operator

            for i, line in enumerate(lines):
                line = line.strip()
                if "=" not in line or not any(c + "b(" in line for c in self.ALPHABET):
                    continue
                if "+" not in line or ", 0)" not in line:
                    continue
                if "^" not in line or "i32_wrap_i64(" not in line:
                    if i + 1 < len(lines) and (
                        "^" in lines[i + 1] and "i32_wrap_i64(" in lines[i + 1]
                    ):
                        line += " " + lines[i + 1].strip()
                    else:
                        continue
                parts = line.split("+")
                if len(parts) < 2:
                    continue
                after_plus = parts[1].strip()
                if "," not in after_plus:
                    continue
                clean_number = "".join(
                    c for c in after_plus.split(",")[0].strip() if c.isdigit()
                )
                if clean_number.isdigit() and clean_number.startswith("10"):
                    result["key_factor2"] = int(clean_number)
                    break

            return result
        return {}

    def _generate_n_key(self):
        seed = self.key_factors["seed"]
        key_factor1 = self.key_factors["key_factor1"]
        key_factor2 = self.key_factors["key_factor2"]

        # start with the first 2 bytes of the key_seed in little format
        # the key_seed is a 32 bit value but hcaptcha only uses the first 2 bytes
        key_bytes = list(self.key_factors["key_seed"].to_bytes(4, byteorder="little"))[
            :2
        ]

        # generate the remaining 30 bytes of the key
        for step in range(30):
            # for all steps except the first update the state seed using a LCG
            if step != 0:
                # multiply the seed by a large constant (LCG multiplier)
                seed = (seed * self.LCG_MULTIPLIER) & 0xFFFFFFFFFFFFFFFF

                # apply the first factor with the specified operator (+ or -)
                if self.key_factors["operator"] == "+":
                    seed = (seed + key_factor1) & 0xFFFFFFFFFFFFFFFF
                else:
                    seed = (seed - key_factor1) & 0xFFFFFFFFFFFFFFFF

            # calculate the base index for memory access
            base_index = self.key_factors["memory"] + step

            # add key_factor2 to the base index for actual memory access
            memory_position = base_index + key_factor2

            # calculate the memory address for accessing segment value
            segment_address = (
                ((memory_position // 320) << 3) + memory_position + 1032 - 1075552
            )

            # get the mask address using modulo 96 and an offset of 8
            mask_address = (memory_position % 96) + 8

            # read a 32 bit value from memory at the segment address
            segment_address %= len(self._memory)
            if segment_address + 4 <= len(self._memory):
                segment_bytes = self._memory[segment_address : segment_address + 4]
            else:
                wrap = segment_address + 4 - len(self._memory)
                segment_bytes = self._memory[segment_address:] + self._memory[:wrap]
            segment_value = int.from_bytes(segment_bytes, byteorder="little")

            # read a 64 bit value from memory at the mask address
            mask_address %= len(self._memory)
            if mask_address + 8 <= len(self._memory):
                mask_bytes = self._memory[mask_address : mask_address + 8]
            else:
                wrap = mask_address + 8 - len(self._memory)
                mask_bytes = self._memory[mask_address:] + self._memory[:wrap]
            mask_value = int.from_bytes(mask_bytes, byteorder="little")

            # calculate a hash value by xoring the segment value with the lower 32 bits of the mask value
            hash_value = (segment_value ^ (mask_value & 0xFFFFFFFF)) & 0xFF

            # extract specific bit positions from the state seed
            # these are at positions 45, 27, and 59 in the 64 bit seed
            bit45 = (seed >> 45) & 0xFFFFFFFF
            bit27 = (seed >> 27) & 0xFFFFFFFF
            bit59 = (seed >> 59) & 0xFFFFFFFF

            # normalize the bit values to signed 32 bit integers if needed
            if bit45 & 0x80000000:
                bit45 = bit45 - 0x100000000
            if bit27 & 0x80000000:
                bit27 = bit27 - 0x100000000
            if bit59 & 0x80000000:
                bit59 = bit59 - 0x100000000

            # xor bit45 and bit27
            combined = bit45 ^ bit27

            # rotate the combined value right by bit59 bits (modulo 32)
            shift = bit59 % 32
            combined &= 0xFFFFFFFF
            rotated = ((combined >> shift) | (combined << (32 - shift))) & 0xFFFFFFFF

            # normalize the rotated value if needed
            if rotated & 0x80000000:
                rotated = rotated - 0x100000000

            # calculate the final key byte by xoring the hash value with the rotated value
            key_byte = (hash_value ^ rotated) & 0xFF

            # add the calculated byte to the key
            key_bytes.append(key_byte)

        # convert the byte array to a hex string to get the final key
        self.key = bytes(key_bytes).hex()


version = "5fef759e34a955dd56ceddd805e6a87d3f7d854c8c695bf797d43331bebfee3f"
extractor = HCaptchaKey(version)
n_key = extractor.run()
print(f"encryption key: {n_key}")