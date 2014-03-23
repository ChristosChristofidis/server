package openbns.commons.crypt;

import java.math.BigInteger;
import java.util.Random;

/**
 * Created with IntelliJ IDEA.
 * User: Eugene Chipachenko
 * Date: 22.03.14
 * Time: 15:14
 */
public class ExBigInteger extends BigInteger
{
  public ExBigInteger( byte[] val )
  {
    super( val );
  }

  public ExBigInteger( int signum, byte[] magnitude )
  {
    super( signum, magnitude );
  }

  public ExBigInteger( String val, int radix )
  {
    super( val, radix );
  }

  public ExBigInteger( String val )
  {
    super( val );
  }

  public ExBigInteger( int numBits, Random rnd )
  {
    super( numBits, rnd );
  }

  public ExBigInteger( int bitLength, int certainty, Random rnd )
  {
    super( bitLength, certainty, rnd );
  }

  @Override
  public byte[] toByteArray()
  {
    byte[] array = super.toByteArray();
    if( array[ 0 ] == 0 )
    {
      byte[] tmp = new byte[ array.length - 1 ];
      System.arraycopy( array, 1, tmp, 0, tmp.length );
      array = tmp;
    }
    return array;
  }
}
