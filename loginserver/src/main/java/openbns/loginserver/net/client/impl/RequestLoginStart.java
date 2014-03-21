package openbns.loginserver.net.client.impl;

import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.Unpooled;
import openbns.commons.crypt.AbstractKeyExchange;
import openbns.commons.crypt.CryptUtil;
import openbns.commons.net.codec.sts.DefaultLastStsContent;
import openbns.commons.net.codec.sts.DefaultStsResponse;
import openbns.commons.net.codec.sts.StsHeaders;
import openbns.commons.net.codec.sts.StsResponseStatus;
import openbns.commons.xml.StsXStream;
import openbns.loginserver.dao.AccountDAO;
import openbns.loginserver.model.Account;
import openbns.loginserver.net.client.AbstractRequestPacket;
import openbns.loginserver.net.client.dto.LoginStartDTO;
import openbns.loginserver.net.server.dto.ReplyErrorDTO;
import openbns.loginserver.net.server.dto.ReplyKeyData;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Created with IntelliJ IDEA.
 * User: Eugene Chipachenko
 * Date: 27.01.14
 * Time: 21:11
 */
public class RequestLoginStart extends AbstractRequestPacket
{
  private LoginStartDTO loginStart;

  @Override
  public void read()
  {
    StsXStream stream = new StsXStream();
    stream.processAnnotations( LoginStartDTO.class );

    loginStart = (LoginStartDTO) stream.fromXML( new ByteBufInputStream( buf ) );
  }

  @Override
  public void execute()
  {
    try
    {
      Account account = AccountDAO.getInstance().getByLogin( loginStart.getLoginName() );
      getHandler().setAccount( account );
      getHandler().getKeyExchange().setUser( account.getLogin() );
      getHandler().getKeyExchange().setPasswordHash( account.getPassword() );

      byte[] bk = getHandler().getKeyExchange().getKeyExchange( AbstractKeyExchange.Mode.SERVER );
      byte[] sk = getHandler().getKeyExchange().getSessionBytes();

      ByteBuffer buffer = ByteBuffer.allocate( bk.length + sk.length + 8 );
      buffer.order( ByteOrder.LITTLE_ENDIAN );

      buffer.clear();
      buffer.putInt( sk.length );
      buffer.put( sk );
      buffer.putInt( bk.length );
      buffer.put( bk );
      buffer.flip();

      String kd = CryptUtil.base64( buffer.array() );

      ReplyKeyData replyKeyData = new ReplyKeyData();
      replyKeyData.setKeyData( kd );

      StsXStream stream = new StsXStream();
      stream.processAnnotations( ReplyKeyData.class );
      byte[] b = stream.toXML( replyKeyData ).getBytes();

      DefaultStsResponse resp = new DefaultStsResponse( StsResponseStatus.OK );
      resp.headers().add( StsHeaders.Names.CONTENT_LENGTH, b.length );
      resp.headers().add( StsHeaders.Names.SESSION_NUMBER, getHandler().getSessionId() + "R" );

      channel.writeAndFlush( resp );
      channel.writeAndFlush( new DefaultLastStsContent( Unpooled.wrappedBuffer( b ) ) );
    }
    catch( NullPointerException e )
    {
      StsXStream stream = new StsXStream();
      stream.processAnnotations( ReplyErrorDTO.class );

      ReplyErrorDTO error = new ReplyErrorDTO();
      error.setCode( 3002 );
      error.setServer( 1001 );
      error.setModule( 1 );
      error.setLine( 458 );
      byte[] b = stream.toXML( error ).getBytes();

      DefaultStsResponse resp = new DefaultStsResponse( StsResponseStatus.NOT_ONLINE );
      resp.headers().add( StsHeaders.Names.CONTENT_LENGTH, b.length );
      resp.headers().add( StsHeaders.Names.SESSION_NUMBER, getHandler().getSessionId() + "R" );

      channel.writeAndFlush( resp );
      channel.writeAndFlush( new DefaultLastStsContent( Unpooled.wrappedBuffer( b ) ) );
    }
    catch( Exception e )
    {
      e.printStackTrace();
    }
  }
}
