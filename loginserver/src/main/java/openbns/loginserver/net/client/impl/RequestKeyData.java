package openbns.loginserver.net.client.impl;

import io.netty.buffer.ByteBufInputStream;
import openbns.commons.crypt.AbstractKeyExchange;
import openbns.commons.crypt.CryptUtil;
import openbns.commons.xml.StsXStream;
import openbns.loginserver.net.client.AbstractRequestPacket;
import openbns.loginserver.net.client.dto.KeyDataDTO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Created with IntelliJ IDEA.
 * User: Eugene Chipachenko
 * Date: 27.01.14
 * Time: 21:14
 */
public class RequestKeyData extends AbstractRequestPacket
{
  private static final Log log = LogFactory.getLog( RequestKeyData.class );
  private KeyDataDTO keyData;

  @Override
  public void read()
  {
    StsXStream stream = new StsXStream();
    stream.processAnnotations( KeyDataDTO.class );
    keyData = (KeyDataDTO) stream.fromXML( new ByteBufInputStream( buf ) );
    log.debug( "Read from client object: " + keyData );
  }

  @Override
  public void execute()
  {
    byte[] data = CryptUtil.base64( keyData.getKeyData() );
    ByteBuffer bf = ByteBuffer.wrap( data );
    bf.order( ByteOrder.LITTLE_ENDIAN );

    int size1 = bf.getInt();
    byte[] exchangeKey = new byte[ size1 ];
    bf.get( exchangeKey );

    int size2 = bf.getInt();
    byte[] checkHash = new byte[ size2 ];
    bf.get( checkHash );

    try
    {
      handler.getKeyExchange().generateKey( AbstractKeyExchange.Mode.SERVER, exchangeKey );

      String checkHashStr = CryptUtil.base64( checkHash );
      String hash = handler.getKeyExchange().getAuthentication();

      String[] args = hash.split( "," );

      if( checkHashStr.equals( args[ 0 ] ) )
      {
        System.out.println( "Authorisation successful" );
      }
      System.out.println( hash );
    }
    catch( Exception e )
    {
      e.printStackTrace();
    }

    System.out.println( new String( exchangeKey ) );
    System.out.println( new String( checkHash ) );
  }
}
