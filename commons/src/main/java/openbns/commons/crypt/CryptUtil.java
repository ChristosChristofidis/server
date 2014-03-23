package openbns.commons.crypt;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created with IntelliJ IDEA.
 * User: Eugene Chipachenko
 * Date: 01.02.14
 * Time: 22:45
 */
public class CryptUtil
{

  public static byte[] hexStringToByteArray( String s )
  {
    int len = s.length();
    byte[] data = new byte[ len / 2 ];
    for( int i = 0; i < len; i += 2 )
    {
      data[ i / 2 ] = (byte) ((Character.digit( s.charAt( i ), 16 ) << 4) + Character.digit( s.charAt( i + 1 ), 16 ));
    }
    return data;
  }

  public static byte[] bigIntegerToArray( BigInteger i )
  {
    byte[] array = i.toByteArray();
    System.out.println( Arrays.toString( array ) );
    if( array[ 0 ] == 0 )
    {
      byte[] tmp = new byte[ array.length - 1 ];
      System.arraycopy( array, 1, tmp, 0, tmp.length );
      array = tmp;
    }
    return array;
  }

  public static byte[] sha256bytes( byte[] data )
  {
    try
    {
      MessageDigest digest = MessageDigest.getInstance( "SHA-256" );
      digest.update( data );
      return digest.digest();
    }
    catch( NoSuchAlgorithmException e )
    {
      e.printStackTrace();
    }
    return null;
  }

  public static String base64( byte[] data )
  {
    return DatatypeConverter.printBase64Binary( data );
  }

  public static byte[] base64( String data )
  {
    return DatatypeConverter.parseBase64Binary( data );
  }

  public static byte[] mergeArrays( byte[]... arrays )
  {
    int size = 0;

    for( byte[] a : arrays )
      size += a.length;

    byte[] result = new byte[ size ];

    int lastPos = 0;
    for( byte[] a : arrays )
    {
      System.arraycopy( a, 0, result, lastPos, a.length );
      lastPos += a.length;
    }
    return result;
  }
}
