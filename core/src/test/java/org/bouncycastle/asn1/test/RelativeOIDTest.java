package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class RelativeOIDTest
    extends SimpleTest
{
    private static final byte[] req1 = Hex.decode("0D03813403");
    private static final byte[] req2 = Hex.decode("0D082A36FFFFFFDD6311");

    public String getName()
    {
        return "RelativeOID";
    }

    private void recodeCheck(String oid, byte[] enc) throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(enc);
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        ASN1RelativeOID o = new ASN1RelativeOID(oid);
        ASN1RelativeOID encO = (ASN1RelativeOID)aIn.readObject();

        if (!o.equals(encO))
        {
            fail("relative OID didn't match", o, encO);
        }

        byte[] bytes = o.getEncoded(ASN1Encoding.DER);

        if (bytes.length != enc.length)
        {
            fail("failed length test");
        }

        for (int i = 0; i != enc.length; i++)
        {
            if (bytes[i] != enc[i])
            {
                fail("failed comparison test", new String(Hex.encode(enc)), new String(Hex.encode(bytes)));
            }
        }
    }

    private void checkValid(String oid) throws IOException
    {
        ASN1RelativeOID o = new ASN1RelativeOID(oid);
        o = (ASN1RelativeOID)ASN1Primitive.fromByteArray(o.getEncoded());
        if (!o.getId().equals(oid))
        {
            fail("failed relative oid check for " + oid);
        }
    }

    private void checkInvalid(String oid)
    {
        try
        {
            new ASN1RelativeOID(oid);
            fail("failed to catch bad relative oid: " + oid);
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void branchCheck(String stem, String branch)
    {
        String expected = stem + "." + branch;
        String actual = new ASN1RelativeOID(stem).branch(branch).getId();

        if (!expected.equals(actual))
        {
            fail("failed 'branch' check for " + stem + "/" + branch);
        }
    }

    private static byte[] encodeRelativeOid(int tag, int contentsLength)
    {
        // tag 82 LL LL followed by contentsLength single-octet subidentifiers
        byte[] enc = new byte[4 + contentsLength];
        enc[0] = (byte)tag;
        enc[1] = (byte)0x82;
        enc[2] = (byte)(contentsLength >> 8);
        enc[3] = (byte)contentsLength;
        for (int i = 4; i < enc.length; i++)
        {
            enc[i] = 0x01;
        }
        return enc;
    }

    private static String repeatedRelativeOid(String stem, int count)
    {
        StringBuffer sb = new StringBuffer(stem);
        for (int i = 0; i < count; i++)
        {
            sb.append(".1");
        }
        return sb.toString();
    }

    private void contentsLengthLimitCheck()
        throws IOException
    {
        String limitMessage = "exceeded relative OID contents length limit";

        // relative OID contents are limited to 4096 octets
        ASN1RelativeOID maxOid = (ASN1RelativeOID)new ASN1InputStream(encodeRelativeOid(0x0D, 4096)).readObject();
        isTrue("4096 octet relative OID not parsed", maxOid.getEncoded().length == 4 + 4096);
        isEquals("4096 octet relative OID mis-parsed", repeatedRelativeOid("1", 4095), maxOid.getId());

        try
        {
            new ASN1InputStream(encodeRelativeOid(0x0D, 4097)).readObject();
            fail("no exception on 4097 octet relative OID");
        }
        catch (IOException e)
        {
            isEquals(limitMessage, e.getMessage());
            isTrue("unexpected cause: " + e.getCause(), e.getCause() instanceof IllegalArgumentException);
        }

        try
        {
            new ASN1StreamParser(encodeRelativeOid(0x0D, 4097)).readObject();
            fail("no exception on 4097 octet relative OID via stream parser");
        }
        catch (IOException e)
        {
            isEquals(limitMessage, e.getMessage());
        }

        try
        {
            ASN1RelativeOID.getInstance(encodeRelativeOid(0x0D, 4097));
            fail("no exception on 4097 octet relative OID via getInstance");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        byte[] overLimitContents = new byte[4097];
        for (int i = 0; i < overLimitContents.length; i++)
        {
            overLimitContents[i] = 0x01;
        }
        // a single over-long subidentifier
        byte[] bigArcContents = new byte[20000];
        for (int i = 0; i < bigArcContents.length - 1; i++)
        {
            bigArcContents[i] = (byte)0xFF;
        }
        bigArcContents[bigArcContents.length - 1] = 0x7F;

        try
        {
            ASN1RelativeOID.fromContents(overLimitContents);
            fail("no exception on 4097 octet relative OID contents");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(limitMessage, e.getMessage());
        }

        try
        {
            ASN1RelativeOID.fromContents(bigArcContents);
            fail("no exception on over-long relative OID subidentifier");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(limitMessage, e.getMessage());
        }

        // implicitly tagged, parsed
        ASN1TaggedObject tagged = (ASN1TaggedObject)new ASN1InputStream(encodeRelativeOid(0x80, 4097)).readObject();
        try
        {
            ASN1RelativeOID.getInstance(tagged, false);
            fail("no exception on 4097 octet parsed implicitly tagged relative OID");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(limitMessage, e.getMessage());
        }

        // each "1" encodes as a single octet
        isTrue(new ASN1RelativeOID(repeatedRelativeOid("1", 4095)).getEncoded().length == 4 + 4096);
        try
        {
            new ASN1RelativeOID(repeatedRelativeOid("1", 4096));
            fail("no exception on 4097 octet relative OID string");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(limitMessage, e.getMessage());
        }

        StringBuffer bigArc = new StringBuffer();
        for (int i = 0; i < 12000; i++)
        {
            bigArc.append('9');
        }
        try
        {
            new ASN1RelativeOID(bigArc.toString());
            fail("no exception on relative OID string with over-long subidentifier");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(limitMessage, e.getMessage());
        }

        StringBuffer longArc = new StringBuffer();
        for (int i = 0; i < 4 * 4096; i++)
        {
            longArc.append('9');
        }
        try
        {
            new ASN1RelativeOID(longArc.toString());
            fail("no exception on over-long relative OID string");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(limitMessage, e.getMessage());
        }

        ASN1RelativeOID stem = new ASN1RelativeOID(repeatedRelativeOid("1", 4094));
        ASN1RelativeOID maxBranch = stem.branch("1");
        isTrue(maxBranch.getEncoded().length == 4 + 4096);
        isEquals(maxOid, maxBranch);
        try
        {
            stem.branch("1.1");
            fail("no exception on 4097 octet relative OID branch");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(limitMessage, e.getMessage());
        }
        try
        {
            new ASN1RelativeOID("1.2").branch(longArc.toString());
            fail("no exception on over-long relative OID branch string");
        }
        catch (IllegalArgumentException e)
        {
            isEquals(limitMessage, e.getMessage());
        }
    }

    public void performTest()
        throws IOException
    {
        recodeCheck("180.3", req1);
        recodeCheck("42.54.34359733987.17", req2);

        checkValid("0");
        checkValid("37");
        checkValid("0.1");
        checkValid("1.0");
        checkValid("1.0.2");
        checkValid("1.0.20");
        checkValid("1.0.200");
        checkValid("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
        checkValid("1.2.123.12345678901.1.1.1");
        checkValid("2.25.196556539987194312349856245628873852187.1");
        checkValid("3.1");
        checkValid("37.196556539987194312349856245628873852187.100");
        checkValid("192.168.1.1");

        checkInvalid("00");
        checkInvalid("0.01");
        checkInvalid("00.1");
        checkInvalid("1.00.2");
        checkInvalid("1.0.02");
        checkInvalid("1.2.00");
        checkInvalid(".1");
        checkInvalid("..1");
        checkInvalid("3..1");
        checkInvalid(".123452");
        checkInvalid("1.");
        checkInvalid("1.345.23.34..234");
        checkInvalid("1.345.23.34.234.");
        checkInvalid(".12.345.77.234");
        checkInvalid(".12.345.77.234.");
        checkInvalid("1.2.3.4.A.5");
        checkInvalid("1,2");

        branchCheck("1.1", "2.2");

        contentsLengthLimitCheck();
    }

    public static void main(String[] args)
    {
        runTest(new RelativeOIDTest());
    }
}
