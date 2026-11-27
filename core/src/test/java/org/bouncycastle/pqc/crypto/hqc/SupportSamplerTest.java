package org.bouncycastle.pqc.crypto.hqc;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Regression tests for HQC's fixed-weight vector sampler,
 * {@code HQCEngine.generateRandomFixedWeight}.
 * <p>
 * The sampler used to reduce each candidate with a variable-latency {@code %} division and
 * branch on every collision found by its duplicate scan; it is now branch-free and fixed-count.
 * That rewrite must not change a single output bit or the number of bytes drawn from the
 * generator - several sampler calls share one generator in key generation and encryption, so
 * drawing a different amount would silently change every generated key and ciphertext. The
 * data-dependent sampler is kept here verbatim as the reference.
 */
public class SupportSamplerTest
    extends TestCase
{
    private static final HQCParameters[] PARAMETER_SETS = new HQCParameters[]{
        HQCParameters.hqc128,
        HQCParameters.hqc192,
        HQCParameters.hqc256
    };

    /**
     * KeccakRandomGenerator that replays a scripted byte stream, so a test can feed the sampler
     * collisions and extreme candidates on demand, and count how much it draws.
     */
    private static class ScriptedGenerator
        extends KeccakRandomGenerator
    {
        private final byte[] stream;
        private int pos;
        int calls;

        ScriptedGenerator(byte[] stream)
        {
            super(256);
            this.stream = stream;
        }

        public void expandSeed(byte[] output, int outLen)
        {
            System.arraycopy(stream, pos, output, 0, outLen);
            pos += outLen;
            calls++;
        }

        int position()
        {
            return pos;
        }
    }

    /**
     * The pre-hardening sampler: {@code %} reduction, and a branch on each duplicate found.
     */
    private static void referenceGenerateRandomFixedWeight(long[] output, KeccakRandomGenerator random,
        int weight, int n, int wr, int nByte64)
    {
        int[] rand_u32 = new int[wr];
        byte[] rand_bytes = new byte[wr * 4];
        int[] support = new int[wr];
        int[] index_tab = new int[wr];
        long[] bit_tab = new long[wr];

        random.expandSeed(rand_bytes, 4 * weight);
        Pack.littleEndianToInt(rand_bytes, 0, rand_u32, 0, rand_u32.length);

        for (int i = 0; i < weight; i++)
        {
            support[i] = (int) (i + ((rand_u32[i]&0xFFFFFFFFL) % (n - i)));
        }

        for (int i = (weight - 1); i >= 0; i--)
        {
            int found = 0;
            for (int j = i + 1; j < weight; j++)
            {
                if (support[j] == support[i])
                {
                    found |= 1;
                }
            }

            int mask = -found;
            support[i] = (mask & i) ^ (~mask & support[i]);
        }

        for (int i = 0; i < weight; i++)
        {
            index_tab[i] = support[i] >>> 6;
            int pos = support[i] & 0x3f;
            bit_tab[i] = (1L) << pos;
        }
        long val = 0;
        for (int i = 0; i < nByte64; i++)
        {
            val = 0;
            for (int j = 0; j < weight; j++)
            {
                int tmp = i - index_tab[j];
                int val1 = 1 ^ ((tmp | -tmp) >>> 31);
                long mask = -val1;
                val |= (bit_tab[j] & mask);
            }
            output[i] |= val;
        }
    }

    private static Method samplerMethod()
        throws Exception
    {
        Method m = HQCEngine.class.getDeclaredMethod("generateRandomFixedWeight",
            new Class[]{long[].class, KeccakRandomGenerator.class, Integer.TYPE});
        m.setAccessible(true);
        return m;
    }

    private static int intField(HQCEngine engine, String name)
        throws Exception
    {
        Field f = HQCEngine.class.getDeclaredField(name);
        f.setAccessible(true);
        return ((Integer)f.get(engine)).intValue();
    }

    private static void runSampler(Method sampler, HQCEngine engine, long[] output,
        KeccakRandomGenerator random, int weight)
        throws Exception
    {
        sampler.invoke(engine, new Object[]{output, random, Integer.valueOf(weight)});
    }

    private static KeccakRandomGenerator seededGenerator(byte[] seed)
    {
        KeccakRandomGenerator random = new KeccakRandomGenerator(256);
        random.seedExpanderInit(seed, seed.length);
        return random;
    }

    private static void assertFixedWeight(String label, long[] v, int weight, int n)
    {
        int bits = 0;
        for (int i = 0; i != v.length; i++)
        {
            bits += Long.bitCount(v[i]);
        }
        assertEquals(label + ": weight", weight, bits);

        // no position at or above n may be set
        for (int pos = n; pos < 64 * v.length; pos++)
        {
            assertEquals(label + ": position " + pos + " set", 0L, v[pos >>> 6] & (1L << (pos & 0x3F)));
        }
    }

    /**
     * The sampler must reproduce the data-dependent reference bit for bit, and leave the
     * generator at the same point, for every parameter set, every weight it is called with and
     * many seeds.
     */
    public void testMatchesReferenceSampler()
        throws Exception
    {
        Method sampler = samplerMethod();

        for (int p = 0; p != PARAMETER_SETS.length; p++)
        {
            HQCEngine engine = PARAMETER_SETS[p].getEngine();
            int n = intField(engine, "n");
            int w = intField(engine, "w");
            int wr = intField(engine, "wr");
            int we = intField(engine, "we");
            int nByte64 = intField(engine, "N_BYTE_64");

            int[] weights = new int[]{w, wr, we};
            for (int wi = 0; wi != weights.length; wi++)
            {
                int weight = weights[wi];
                for (int s = 0; s != 200; s++)
                {
                    byte[] seed = new byte[40];
                    Pack.intToBigEndian(s, seed, 0);
                    seed[39] = (byte)p;
                    seed[38] = (byte)wi;

                    KeccakRandomGenerator expectedRandom = seededGenerator(seed);
                    KeccakRandomGenerator actualRandom = seededGenerator(seed);

                    long[] expected = new long[nByte64];
                    long[] actual = new long[nByte64];

                    referenceGenerateRandomFixedWeight(expected, expectedRandom, weight, n, wr, nByte64);
                    runSampler(sampler, engine, actual, actualRandom, weight);

                    String label = PARAMETER_SETS[p].getName() + " weight=" + weight + " seed=" + s;
                    assertTrue(label + ": vector differs", Arrays.areEqual(expected, actual));

                    // the same number of bytes must have been consumed
                    byte[] nextExpected = new byte[64];
                    byte[] nextActual = new byte[64];
                    expectedRandom.expandSeed(nextExpected, nextExpected.length);
                    actualRandom.expandSeed(nextActual, nextActual.length);
                    assertTrue(label + ": generator position differs", Arrays.areEqual(nextExpected, nextActual));

                    // and the vector must hold exactly weight distinct positions in [0, n)
                    assertFixedWeight(label, actual, weight, n);
                }
            }
        }
    }

    /**
     * The call sequences of key generation (x, y from one generator) and encryption (r1, r2, e
     * from one generator) must be unchanged, as every later call depends on what the earlier
     * ones drew.
     */
    public void testSharedGeneratorSequences()
        throws Exception
    {
        Method sampler = samplerMethod();

        for (int p = 0; p != PARAMETER_SETS.length; p++)
        {
            HQCEngine engine = PARAMETER_SETS[p].getEngine();
            int n = intField(engine, "n");
            int w = intField(engine, "w");
            int wr = intField(engine, "wr");
            int we = intField(engine, "we");
            int nByte64 = intField(engine, "N_BYTE_64");

            int[][] sequences = new int[][]{{w, w}, {wr, wr, we}};
            for (int q = 0; q != sequences.length; q++)
            {
                for (int s = 0; s != 25; s++)
                {
                    byte[] seed = new byte[40];
                    seed[0] = (byte)s;
                    seed[1] = (byte)p;
                    seed[2] = (byte)q;

                    KeccakRandomGenerator expectedRandom = seededGenerator(seed);
                    KeccakRandomGenerator actualRandom = seededGenerator(seed);

                    for (int c = 0; c != sequences[q].length; c++)
                    {
                        int weight = sequences[q][c];
                        long[] expected = new long[nByte64];
                        long[] actual = new long[nByte64];

                        referenceGenerateRandomFixedWeight(expected, expectedRandom, weight, n, wr, nByte64);
                        runSampler(sampler, engine, actual, actualRandom, weight);

                        String label = PARAMETER_SETS[p].getName() + " sequence=" + q + " call=" + c + " seed=" + s;
                        assertTrue(label + ": vector differs", Arrays.areEqual(expected, actual));
                        assertFixedWeight(label, actual, weight, n);
                    }
                }
            }
        }
    }

    /**
     * Collision-heavy input with extreme candidates: the stream the old duplicate scan branched
     * on. Every candidate is built to land on one position V, either directly, through an alias
     * a multiple of (n - i) higher, or as the largest unsigned alias below 2^32; the rest are
     * 0xFFFFFFFF, which only an unsigned reduction handles correctly. The sampler must agree
     * with the reference, produce exactly weight positions with V among them, and draw exactly
     * 4 * weight bytes in one call.
     */
    public void testAdversarialCollisionStream()
        throws Exception
    {
        Method sampler = samplerMethod();

        for (int p = 0; p != PARAMETER_SETS.length; p++)
        {
            HQCEngine engine = PARAMETER_SETS[p].getEngine();
            int n = intField(engine, "n");
            int w = intField(engine, "w");
            int wr = intField(engine, "wr");
            int we = intField(engine, "we");
            int nByte64 = intField(engine, "N_BYTE_64");

            int[] weights = new int[]{w, wr, we};
            for (int wi = 0; wi != weights.length; wi++)
            {
                int weight = weights[wi];
                int target = weight + 7;

                byte[] stream = new byte[4 * weight];
                for (int i = 0; i != weight; i++)
                {
                    long d = n - i;
                    long direct = target - i;
                    long value;
                    switch (i % 4)
                    {
                    case 0:
                        value = direct;
                        break;
                    case 1:
                        value = direct + d;
                        break;
                    case 2:
                        value = direct + ((0xFFFFFFFFL - direct) / d) * d;
                        break;
                    default:
                        value = 0xFFFFFFFFL;
                        break;
                    }
                    Pack.intToLittleEndian((int)value, stream, 4 * i);
                }

                ScriptedGenerator expectedRandom = new ScriptedGenerator(stream);
                ScriptedGenerator actualRandom = new ScriptedGenerator(stream);

                long[] expected = new long[nByte64];
                long[] actual = new long[nByte64];

                referenceGenerateRandomFixedWeight(expected, expectedRandom, weight, n, wr, nByte64);
                runSampler(sampler, engine, actual, actualRandom, weight);

                String label = PARAMETER_SETS[p].getName() + " weight=" + weight;
                assertEquals(label + ": calls", 1, actualRandom.calls);
                assertEquals(label + ": bytes consumed", expectedRandom.position(), actualRandom.position());
                assertEquals(label + ": bytes consumed", 4 * weight, actualRandom.position());
                assertTrue(label + ": vector differs", Arrays.areEqual(expected, actual));
                assertFixedWeight(label, actual, weight, n);
                assertTrue(label + ": colliding position missing",
                    (actual[target >>> 6] & (1L << (target & 0x3F))) != 0);
            }
        }
    }

    /**
     * The constant-time remainder that replaced {@code %} must agree with it on every divisor
     * the sampler uses, for the extreme and boundary dividends and a spread of random ones,
     * treating the dividend as unsigned.
     */
    public void testConstantTimeRemainder()
        throws Exception
    {
        Method rem = HQCEngine.class.getDeclaredMethod("ctRemainder", new Class[]{Integer.TYPE, Integer.TYPE});
        rem.setAccessible(true);

        Random rand = new Random(0x18040L);

        for (int p = 0; p != PARAMETER_SETS.length; p++)
        {
            HQCEngine engine = PARAMETER_SETS[p].getEngine();
            int n = intField(engine, "n");
            int wr = intField(engine, "wr");

            for (int d = n - wr; d <= n; d++)
            {
                checkRemainder(rem, d, rand);
            }
        }

        int[] divisors = new int[]{1, 2, 3, 7, 255, 256, 65535, 65536, 0x7FFFFFFE, 0x7FFFFFFF};
        for (int i = 0; i != divisors.length; i++)
        {
            checkRemainder(rem, divisors[i], rand);
        }
    }

    private static void checkRemainder(Method rem, int d, Random rand)
        throws Exception
    {
        long[] xs = new long[]{0L, 1L, d - 1L, d, d + 1L, 2L * d - 1, 2L * d, 0x7FFFFFFFL, 0x80000000L,
            0xFFFFFFFEL, 0xFFFFFFFFL, (0xFFFFFFFFL / d) * d, (0xFFFFFFFFL / d) * d - 1};
        for (int i = 0; i != xs.length + 64; i++)
        {
            long x = (i < xs.length ? xs[i] : rand.nextInt()) & 0xFFFFFFFFL;
            int expected = (int)(x % d);
            int actual = ((Integer)rem.invoke(null, new Object[]{Integer.valueOf((int)x), Integer.valueOf(d)})).intValue();
            assertEquals("ctRemainder(" + x + ", " + d + ")", expected, actual);
        }
    }

    /**
     * The leak itself: the vulnerable sampler compiled its duplicate test to a conditional jump
     * taken or not according to whether two secret positions collided, and reduced each secret
     * candidate with a hardware division whose latency depends on its operand. Neither may
     * appear in the sampler or the helpers it uses: no equality-based conditional jump or
     * switch (loop bounds, which only compare public counters, compile to ordering jumps) and no
     * division or remainder instruction. Fails against the unpatched class, whose sampler
     * contains if_icmpne and lrem.
     */
    public void testSamplerHasNoSecretDependentBranchOrDivision()
        throws Exception
    {
        String[] methods = new String[]{"generateRandomFixedWeight", "compareU32", "ctRemainder"};

        for (int m = 0; m != methods.length; m++)
        {
            byte[] code = methodCode(HQCEngine.class, methods[m]);
            assertNotNull("HQCEngine." + methods[m] + " not found", code);

            int pc = 0;
            while (pc < code.length)
            {
                int op = code[pc] & 0xFF;
                String forbidden = forbiddenOpcode(op);
                assertNull("HQCEngine." + methods[m] + " contains " + forbidden + " at pc " + pc, forbidden);
                pc += instructionLength(code, pc);
            }
            assertEquals("HQCEngine." + methods[m] + ": bytecode walk overran", code.length, pc);
        }
    }

    private static String forbiddenOpcode(int op)
    {
        switch (op)
        {
        case 0x6c:
            return "idiv";
        case 0x6d:
            return "ldiv";
        case 0x70:
            return "irem";
        case 0x71:
            return "lrem";
        case 0x99:
            return "ifeq";
        case 0x9a:
            return "ifne";
        case 0x9f:
            return "if_icmpeq";
        case 0xa0:
            return "if_icmpne";
        case 0xa5:
            return "if_acmpeq";
        case 0xa6:
            return "if_acmpne";
        case 0xaa:
            return "tableswitch";
        case 0xab:
            return "lookupswitch";
        case 0xc6:
            return "ifnull";
        case 0xc7:
            return "ifnonnull";
        default:
            return null;
        }
    }

    private static int readInt(byte[] code, int off)
    {
        return ((code[off] & 0xFF) << 24) | ((code[off + 1] & 0xFF) << 16)
            | ((code[off + 2] & 0xFF) << 8) | (code[off + 3] & 0xFF);
    }

    /**
     * Length in bytes of the JVM instruction at {@code pc}.
     */
    private static int instructionLength(byte[] code, int pc)
    {
        int op = code[pc] & 0xFF;
        if ((op >= 0x15 && op <= 0x19) || (op >= 0x36 && op <= 0x3a))
        {
            return 2; // xload / xstore with a local index
        }
        if (op >= 0x99 && op <= 0xa8)
        {
            return 3; // conditional jumps, goto, jsr
        }
        if (op >= 0xb2 && op <= 0xb8)
        {
            return 3; // field access and invokes other than interface/dynamic
        }
        switch (op)
        {
        case 0x10: // bipush
        case 0x12: // ldc
        case 0xa9: // ret
        case 0xbc: // newarray
            return 2;
        case 0x11: // sipush
        case 0x13: // ldc_w
        case 0x14: // ldc2_w
        case 0x84: // iinc
        case 0xbb: // new
        case 0xbd: // anewarray
        case 0xc0: // checkcast
        case 0xc1: // instanceof
        case 0xc6: // ifnull
        case 0xc7: // ifnonnull
            return 3;
        case 0xc5: // multianewarray
            return 4;
        case 0xb9: // invokeinterface
        case 0xba: // invokedynamic
        case 0xc8: // goto_w
        case 0xc9: // jsr_w
            return 5;
        case 0xc4: // wide
            return ((code[pc + 1] & 0xFF) == 0x84) ? 6 : 4;
        case 0xaa: // tableswitch
        {
            int base = (pc + 4) & ~3;
            int low = readInt(code, base + 4);
            int high = readInt(code, base + 8);
            return base - pc + 12 + 4 * (high - low + 1);
        }
        case 0xab: // lookupswitch
        {
            int base = (pc + 4) & ~3;
            int npairs = readInt(code, base + 4);
            return base - pc + 8 + 8 * npairs;
        }
        default:
            return 1;
        }
    }

    /**
     * The bytecode of the named method, read from the class file, or null if it has none.
     */
    private static byte[] methodCode(Class clazz, String methodName)
        throws IOException
    {
        String name = clazz.getName();
        InputStream in = clazz.getResourceAsStream(name.substring(name.lastIndexOf('.') + 1) + ".class");
        assertNotNull("class file for " + name + " not found", in);

        DataInputStream din = new DataInputStream(in);
        try
        {
            assertEquals("class file magic", 0xCAFEBABE, din.readInt());
            din.readUnsignedShort(); // minor_version
            din.readUnsignedShort(); // major_version

            int cpCount = din.readUnsignedShort();
            String[] utf8 = new String[cpCount];
            for (int i = 1; i < cpCount; i++)
            {
                int tag = din.readUnsignedByte();
                switch (tag)
                {
                case 1: // Utf8
                    utf8[i] = din.readUTF();
                    break;
                case 3: // Integer
                case 4: // Float
                case 9: // Fieldref
                case 10: // Methodref
                case 11: // InterfaceMethodref
                case 12: // NameAndType
                case 17: // Dynamic
                case 18: // InvokeDynamic
                    din.readInt();
                    break;
                case 5: // Long
                case 6: // Double
                    din.readLong();
                    i++;
                    break;
                case 7: // Class
                case 8: // String
                case 16: // MethodType
                case 19: // Module
                case 20: // Package
                    din.readUnsignedShort();
                    break;
                case 15: // MethodHandle
                    din.readUnsignedByte();
                    din.readUnsignedShort();
                    break;
                default:
                    throw new IOException("unknown constant pool tag " + tag);
                }
            }

            din.readUnsignedShort(); // access_flags
            din.readUnsignedShort(); // this_class
            din.readUnsignedShort(); // super_class
            int interfaces = din.readUnsignedShort();
            for (int i = 0; i != interfaces; i++)
            {
                din.readUnsignedShort();
            }

            int fields = din.readUnsignedShort();
            for (int i = 0; i != fields; i++)
            {
                din.readUnsignedShort(); // access_flags
                din.readUnsignedShort(); // name_index
                din.readUnsignedShort(); // descriptor_index
                skipAttributes(din);
            }

            int methods = din.readUnsignedShort();
            for (int i = 0; i != methods; i++)
            {
                din.readUnsignedShort(); // access_flags
                String mName = utf8[din.readUnsignedShort()];
                din.readUnsignedShort(); // descriptor_index
                int attributes = din.readUnsignedShort();
                for (int a = 0; a != attributes; a++)
                {
                    String aName = utf8[din.readUnsignedShort()];
                    byte[] data = new byte[din.readInt()];
                    din.readFully(data);
                    if (methodName.equals(mName) && "Code".equals(aName))
                    {
                        // max_stack (u2), max_locals (u2), code_length (u4), code
                        int codeLength = readInt(data, 4);
                        byte[] code = new byte[codeLength];
                        System.arraycopy(data, 8, code, 0, codeLength);
                        return code;
                    }
                }
            }

            return null;
        }
        finally
        {
            din.close();
        }
    }

    private static void skipAttributes(DataInputStream din)
        throws IOException
    {
        int attributes = din.readUnsignedShort();
        for (int a = 0; a != attributes; a++)
        {
            din.readUnsignedShort(); // attribute_name_index
            int len = din.readInt();
            din.readFully(new byte[len]);
        }
    }
}
