package openbns.loginserver.crypt;

import openbns.commons.crypt.AbstractKeyExchange;
import openbns.commons.crypt.CryptUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created with IntelliJ IDEA.
 * User: Eugene Chipachenko
 * Date: 21.03.14
 * Time: 22:10
 */
public class BNSKeyExchange extends AbstractKeyExchange
{
  public static final BigInteger N = new BigInteger( "E306EBC02F1DC69F5B437683FE3851FD9AAA6E97F4CBD42FC06C72053CBCED68EC570E6666F529C58518CF7B299B5582495DB169ADF48ECEB6D65461B4D7C75DD1DA89601D5C498EE48BB950E2D8D5E0E0C692D613483B38D381EA9674DF74D67665259C4C31A29E0B3CFF7587617260E8C58FFA0AF8339CD68DB3ADB90AAFEE", 16 );
  public static final BigInteger P = new BigInteger( "7A39FF57BCBFAA521DCE9C7DEFAB520640AC493E1B6024B95A28390E8F05787D", 16 );
  public static final byte[] staticKey = CryptUtil.hexStringToByteArray( "AC34F3070DC0E52302C2E8DA0E3F7B3E63223697555DF54E7122A14DBC99A3E8" );
  public static final BigInteger two = new BigInteger( "2" );

  private static final SecureRandom rnd = new SecureRandom();
  private static final KeyManager keyManager = KeyManager.getInstance();

  private BigInteger privateKey;
  private BigInteger exchangeKey = two;
  private BigInteger exchangeKeyServer;

  private BigInteger session = new BigInteger( 1, rnd.generateSeed( 8 ) );
  private byte[] passwordHash, usernameHash;
  private String user, authentication;

  private BigInteger getKeyExchange()
  {
    if( exchangeKey.equals( two ) )
      exchangeKey = two.modPow( privateKey, N );
    return exchangeKey;
  }

  public BigInteger getKeyExchangeClient()
  {
    return getKeyExchange();
  }

  private BigInteger getKeyExchangeServer()
  {
    if( exchangeKey.equals( two ) )
    {
      exchangeKey = two.modPow( privateKey, N );
      usernameHash = HashHelper.loginHash( user );
      BigInteger hash2 = keyManager.generateAIIKey( CryptUtil.bigIntegerToArray( session ), passwordHash );
      BigInteger v25 = two.modPow( hash2, N );
      v25 = v25.multiply( P ).mod( N );
      exchangeKeyServer = exchangeKey.add( v25 ).mod( N );
    }
    return exchangeKeyServer;
  }

  public byte[][] generateKeyClient( BigInteger exchangeKey )
  {
    BigInteger hash1 = keyManager.generateAIIKey( CryptUtil.bigIntegerToArray( getKeyExchange() ), CryptUtil.bigIntegerToArray( exchangeKey ) );
    BigInteger hash2 = keyManager.generateAIIKey( CryptUtil.bigIntegerToArray( session ), passwordHash );

    BigInteger v27 = new BigInteger( CryptUtil.bigIntegerToArray( exchangeKey ) );
    BigInteger v25 = two.modPow( hash2, N );
    v25 = v25.multiply( P ).mod( N );

    while( v27.compareTo( v25 ) < 0 )
      v27 = v27.add( N );
    v27 = v27.add( v25.negate() );

    BigInteger v24 = ((hash1.multiply( hash2 )).add( privateKey )).mod( N );
    BigInteger v21 = v27.modPow( v24, N );

    key = keyManager.generateEncryptionKeyRoot( CryptUtil.bigIntegerToArray( v21 ) );
    byte[] chash1 = CryptUtil.sha256bytes( CryptUtil.mergeArrays( staticKey, HashHelper.loginHash( user ), CryptUtil.bigIntegerToArray( session ), CryptUtil.bigIntegerToArray( getKeyExchange() ), CryptUtil.bigIntegerToArray( exchangeKey ), key ) );
    byte[] chash2 = CryptUtil.sha256bytes( CryptUtil.mergeArrays( CryptUtil.bigIntegerToArray( getKeyExchange() ), chash1, key ) );
    key = keyManager.generate256BytesKey( key );

    return new byte[][] { chash1, chash2 };
  }

  public byte[][] generateKeyServer( BigInteger exchangeKey )
  {
    BigInteger hash1 = keyManager.generateAIIKey( CryptUtil.bigIntegerToArray( exchangeKey ), CryptUtil.bigIntegerToArray( getKeyExchangeServer() ) );

    BigInteger hash2 = keyManager.generateAIIKey( CryptUtil.bigIntegerToArray( session ), passwordHash );

    BigInteger v27 = new BigInteger( exchangeKey.toByteArray() );

    //BigInteger v21 = (this.GetKeyExchange().modPow((hash1 * hash2), N) * v27.modPow(privateKey, N)) % N;
    BigInteger v21 = getKeyExchange().modPow( hash1.multiply( hash2 ), N ).multiply( v27.modPow( privateKey, N ) ).mod( N );
    key = keyManager.generateEncryptionKeyRoot( CryptUtil.bigIntegerToArray( v21 ) );

    byte[] chash1 = CryptUtil.sha256bytes( CryptUtil.mergeArrays( staticKey, usernameHash, CryptUtil.bigIntegerToArray( session ), CryptUtil.bigIntegerToArray( exchangeKey ), CryptUtil.bigIntegerToArray( getKeyExchangeServer() ), key ) );
    byte[] chash2 = CryptUtil.sha256bytes( CryptUtil.mergeArrays( CryptUtil.bigIntegerToArray( exchangeKey ), chash1, key ) );
//    key = keyManager.generate256BytesKey( key );

    return new byte[][] { chash1, chash2 };
  }

  @Override
  public void generatePrivateKey()
  {
    long time = System.currentTimeMillis();
    long ticks = 621355968000000000L + time * 10000;
    String s_time = String.valueOf( ticks );
    byte[] b_time = s_time.getBytes();

    privateKey = new BigInteger( 1, CryptUtil.sha256bytes( b_time ) );
  }

  @Override
  public void generateKey( Mode mode, byte[] keyExchange )
  {
    byte[][] checkHash = null;
    BigInteger exchange = new BigInteger( keyExchange );
    switch( mode )
    {
      case CLIENT:
        checkHash = generateKeyClient( exchange );
        break;
      case SERVER:
        checkHash = generateKeyServer( exchange );
        break;
    }
    authentication = CryptUtil.base64( checkHash[ 0 ] ) + "," + CryptUtil.base64( checkHash[ 1 ] );
  }

  @Override
  public byte[] getKeyExchange( Mode mode )
  {
    switch( mode )
    {
      case CLIENT:
        return CryptUtil.bigIntegerToArray( getKeyExchangeClient() );
      case SERVER:
        return CryptUtil.bigIntegerToArray( getKeyExchangeServer() );
    }
    throw new IllegalArgumentException();
  }

  public byte[] getSessionBytes()
  {
    return CryptUtil.bigIntegerToArray( session );
  }

  public String getUser()
  {
    return user;
  }

  public void setUser( String user )
  {
    this.user = user;
  }

  public void setPasswordHash( byte[] passwordHash )
  {
    this.passwordHash = passwordHash;
  }

  public String getAuthentication()
  {
    return authentication;
  }
}
