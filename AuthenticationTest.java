package digital.gartner.common;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AuthenticationTest {
    @Test
    public void test() throws Exception {
        assertTrue(true);
    }

    @Test
    public void generatePasswordToken(){
        Authentication authentication = new Authentication();
        String url = "url";
        String username = "uName";
        String password = "pwd";
        String nonce = "nonce";
        String result = authentication.generatePasswordToken(url, username, password, nonce);
        Assert.assertNotNull(result);
        String passwordHash = authentication.generatePasswordHash(username, password);
        String payload = url + passwordHash + username + nonce;
        Assert.assertEquals(result,HmacUtils.hmacSha256Hex(passwordHash, payload));
    }

    @Test
    public void generatePasswordHashTest(){
        Authentication authentication = new Authentication();
        String username = "uName";
        String password = "pwd";
        String result = authentication.generatePasswordHash(username, password);
        Assert.assertNotNull(result);
        Assert.assertEquals(result, DigestUtils.sha256Hex(username + ":" + password));
    }

    @Test
    public void generateAccessTokenTest(){
        Authentication authentication = new Authentication();
        String publicId = "publicId";
        String secretKey = "secretKey";
        String timeStamp = "timeStamp";

        StringBuilder buf = new StringBuilder();

        buf.append(publicId)
                .append(secretKey)
                .append(timestamp);

        String result = authentication.generateAccessToken(publicId, secretKey, timeStamp);
        Assert.assertEquals(result, HmacUtils.hmacSha256Hex(secretKey, buf.toString()));
    }

    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateAccessTokenTest1(){
        Authentication authentication = new Authentication();
        String result = authentication.generateAccessToken(null, "", "");
        fail();
    }

    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateAccessTokenTest2(){
        Authentication authentication = new Authentication();
        String result = authentication.generateAccessToken("", null, "");
        fail();
    }
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateAccessTokenTest3(){
        Authentication authentication = new Authentication();
        String result = authentication.generateAccessToken("", "", null);
        fail();
    }

    @Test
    public void generateSignatureTest(){
        Authentication authentication = new Authentication();
        String payload = "payload";
        String publicKey = "publicKey";
        String nonce = "nonce";
        String timestamp = "timestamp";
        String accessToken = "accessToken";
        StringBuilder buf = new StringBuilder();
        buf.append(payload)
                .append(timestamp)
                .append(publicKey)
                .append(nonce);
        String result = authentication.generateSignature(payload, publicKey, nonce, timestamp, accessToken);
        Assert.assertEquals(result, HmacUtils.hmacSha256Hex(accessToken, buf.toString()));
    }
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest1() throws Exception{
        Authentication authentication = new Authentication();
        String result = authentication.generateSignature(null, "", "", "", "");
        fail();
    }
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest2() throws Exception{
        Authentication authentication = new Authentication();
        String result = authentication.generateSignature("", null, "", "", "");
        fail();
    }

    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest3() throws Exception{
        Authentication authentication = new Authentication();
        String result = authentication.generateSignature("", "", null, "", "");
        fail();
    }

    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest4() throws Exception{
        Authentication authentication = new Authentication();
        String result = authentication.generateSignature("", "", "", null, "");
        fail();
    }

    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest5() throws Exception{
        Authentication authentication = new Authentication();
        String result = authentication.generateSignature("", "", "", "", null);
        fail();
    }

}
