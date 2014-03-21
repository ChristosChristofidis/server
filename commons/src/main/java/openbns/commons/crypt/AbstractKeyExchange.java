package openbns.commons.crypt;

import java.math.BigInteger;

/**
 * Created with IntelliJ IDEA.
 * User: Eugene Chipachenko
 * Date: 21.03.14
 * Time: 22:03
 */
public abstract class AbstractKeyExchange
{
  public static final BigInteger modulus = new BigInteger( "f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e92f78c7", 16 );
  protected byte[] key;

  public abstract void generatePrivateKey();

  public abstract void generateKey( Mode mode, byte[] keyExchange );

  public abstract byte[] getKeyExchange( Mode mode );

  public byte[] getKey()
  {
    return key;
  }

  public static enum Mode
  {
    CLIENT,
    SERVER
  }
}
