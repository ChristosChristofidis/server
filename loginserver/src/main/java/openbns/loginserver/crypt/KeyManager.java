package openbns.loginserver.crypt;

import openbns.commons.crypt.CryptUtil;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Created with IntelliJ IDEA.
 * User: Eugene Chipachenko
 * Date: 22.01.14
 * Time: 0:08
 */
public class KeyManager
{
  /**
   * Thanks to Luna9966
   */
  private static KeyManager ourInstance = new KeyManager();

  public static KeyManager getInstance()
  {
    return ourInstance;
  }

  private KeyManager()
  {
  }

  public BigInteger generateAIIKey( byte[] tmp1, byte[] tmp2 )
  {
    try
    {
      byte[] sharedArray = new byte[ tmp1.length + tmp2.length ];

      System.arraycopy( tmp1, 0, sharedArray, 0, tmp1.length );
      System.arraycopy( tmp2, 0, sharedArray, tmp1.length, tmp2.length );

      MessageDigest digest = MessageDigest.getInstance( "SHA-256" );
      digest.update( sharedArray );

      byte[] hash = digest.digest();
      byte[] reversed = reverseIntegerArray( hash );
      return new BigInteger( 1,  reversed );
    }
    catch( Exception e )
    {
      e.printStackTrace();
      return null;
    }
  }

  private byte[] reverseIntegerArray( byte[] array ) throws IOException
  {
    byte[] res = new byte[ array.length ];

    for( int i = 0; i < array.length; i += 4 )
    {
      res[ i ] = array[ i + 3 ];
      res[ i + 1 ] = array[ i + 2 ];
      res[ i + 2 ] = array[ i + 1 ];
      res[ i + 3 ] = array[ i ];
    }
    return res;
  }

  public byte[] generateEncryptionKeyRoot( byte[] src )
  {
    int firstSize = src.length;
    int startIndex = 0;
    byte[] half;
    byte[] dst = new byte[ 64 ];
    if( src.length > 4 )
    {
      do
      {
        if( src[ startIndex ] == 0 )
          break;
        firstSize--;
        startIndex++;
      }
      while( firstSize > 4 );
    }
    int size = firstSize >> 1;
    half = new byte[ size ];
    if( size > 0 )
    {
      int index = startIndex + firstSize - 1;
      for( int i = 0; i < size; i++ )
      {
        half[ i ] = src[ index ];
        index -= 2;
      }
    }
    byte[] hash = CryptUtil.sha256bytes( Arrays.copyOfRange( half, 0, size ) );
    for( int i = 0; i < 32; i++ )
    {
      dst[ 2 * i ] = hash[ i ];
    }
    if( size > 0 )
    {
      int index = startIndex + firstSize - 2;
      for( int i = 0; i < size; i++ )
      {
        half[ i ] = src[ index ];
        index -= 2;
      }
    }
    hash = CryptUtil.sha256bytes( Arrays.copyOfRange( half, 0, size ) );
    for( int i = 0; i < 32; i++ )
    {
      dst[ 2 * i + 1 ] = hash[ i ];
    }
    return dst;
  }

  public byte[] generate256BytesKey( byte[] src )
  {
    int v7 = 1;
    byte[] res = new byte[ 256 ];
    for( int i = 0; i < 256; i++ )
      res[ i ] = (byte) i;
    int v6 = 0;
    int counter = 0;
    for( int i = 64; i > 0; i-- )
    {
      int v9 = (v6 + src[ counter ] + res[ v7 - 1 ]) & 0xFF;
      int v10 = res[ v7 - 1 ];
      res[ v7 - 1 ] = res[ v9 ];
      int v8 = counter + 1;
      res[ v9 ] = (byte) v10;
      if( v8 == src.length )
        v8 = 0;
      int v13 = v9 + src[ v8 ];
      int v11 = v8 + 1;
      int v14 = v13 + res[ v7 ];
      v13 = res[ v7 ];
      int v12 = (byte) v14;
      res[ v7 ] = res[ v12 ];
      res[ v12 ] = (byte) v13;
      if( v11 == src.length )
        v11 = 0;
      int v16 = (v12 + src[ v11 ] + res[ v7 + 1 ]) & 0xFF;
      int v17 = res[ v7 + 1 ];
      res[ v7 + 1 ] = res[ v16 ];
      int v15 = v11 + 1;
      res[ v16 ] = (byte) v17;
      if( v15 == src.length )
        v15 = 0;
      int v18 = v16 + src[ v15 ];
      int v19 = res[ v7 + 2 ];
      v6 = (v18 + res[ v7 + 2 ]) & 0xFF;
      counter = v15 + 1;
      res[ v7 + 2 ] = res[ v6 ];
      res[ v6 ] = (byte) v19;
      if( counter == src.length )
        counter = 0;
      v7 += 4;
    }
    return res;
  }
}
