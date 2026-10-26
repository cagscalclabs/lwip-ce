"""Execute the production byte-copy loop's ADL instruction subset.

The entropy call is stubbed; check copy bounds, termination, and return pointer.
This is a source-level instruction simulation, not an eZ80 machine emulator.
"""
from pathlib import Path

source = (Path(__file__).resolve().parents[3] / 'src/tls/core/primitives/random.s').read_text()
body = source.split('_tls_entropy_collect:\n', 1)[1].split('; ---------------------------------------------------------', 1)[0]
code = [line.split(';')[0].strip() for line in body.splitlines()]
code = [line for line in code if line]
labels = {line[:-1]: i for i, line in enumerate(code) if line.endswith(':')}
MASK = 0xffffff


def execute(length):
    regs = {'hl': 0, 'bc': 0xabcdef, 'de': 0, 'ix': 0x1000, 'sp': 0}
    slots = {
        '(ix+6)': 0x2000,
        '(ix+9)': length,
        '(_sprng_random_last_ok)': 1,
    }
    carry = zero = False
    calls = copied = 0
    pc = 0

    def value(x):
        if x in regs:
            return regs[x]
        if x in slots:
            return slots[x]
        if x == '_sprng_sha_digest':
            return 0x100
        if x == '_sprng_entropy_pool':
            return 0x300
        if x == '_sprng_entropy_pool+1':
            return 0x301
        if x == '_sprng_conditioned_bytes':
            return 24
        if x == '_sprng_overlay.size-1':
            return 519
        if x == 'l':
            return regs['hl'] & 255
        return int(x)

    for _ in range(100000):
        line = code[pc]
        pc += 1
        if line.endswith(':'):
            continue
        op, _, args = line.partition(' ')
        args = args.strip()
        if op == 'ld':
            dst, src = args.split(',')
            v = value(src) & MASK
            if dst == 'c':
                regs['bc'] = (regs['bc'] & 0xffff00) | (v & 255)
            elif dst.startswith('('):
                slots[dst] = v
            else:
                regs[dst] = v
        elif op in ('add', 'sbc'):
            dst, src = args.split(',')
            v = regs[dst] + value(src) if op == 'add' else regs[dst] - value(src) - carry
            carry = v < 0 or v > MASK
            regs[dst] = v & MASK
            if op == 'sbc':
                zero = regs[dst] == 0
        elif op == 'or':
            carry = False
            if args == 'a,a':
                zero = (regs.get('a', 0) & 255) == 0
        elif op == 'jr':
            parts = args.split(',')
            conditions = {'z': zero, 'nz': not zero, 'c': carry, 'nc': not carry}
            if len(parts) == 1 or conditions[parts[0]]:
                pc = labels[parts[-1]]
        elif op == 'call':
            if args == '_tls_entropy_gather192':
                calls += 1
                regs.update(hl=0x123456, bc=0xabcdef, de=0x987654)
                slots['(_sprng_random_last_ok)'] = 1
            else:
                assert args == '__frameset'
        elif op == 'ldir':
            count = regs['bc'] or 0x1000000
            if regs['hl'] == 0x100:
                assert 1 <= count <= 24, (length, 'source overread', count)
                assert regs['de'] == 0x2000 + copied
                copied += count
                assert copied <= length, (length, 'destination overwrite', copied)
            else:
                assert regs['hl'] == 0x300
                assert regs['de'] == 0x301
                assert count == 519
            regs['hl'] += count
            regs['de'] += count
            regs['bc'] = 0
        elif op == 'pop':
            assert args == 'ix'
        elif op == 'ret':
            assert copied == length
            assert calls == (length + 23) // 24
            assert regs['hl'] == 0x2000
            return
        else:
            raise AssertionError(line)
    raise AssertionError((length, 'loop did not terminate'))

for size in [*range(257), 511, 512, 513, 4095, 4096, 4097]:
    execute(size)
print('263 RNG length cases passed: bounded 192-bit copies, termination, return pointer')
