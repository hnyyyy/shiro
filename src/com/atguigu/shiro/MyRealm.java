package com.atguigu.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm{
	/**
	 * 当访问受保护的资源时，shiro会调用doGetAuthorizationInfo方法。
	 * 可以从PrincipalCollection类型的参数中来获取当前登录用户的信息
	 */
	//进行授权的方法
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals ) {
		//1.调用 PrincipalCollection 的 getPrimaryPrincipal() 方法来获取登录信息
		Object principal = principals.getPrimaryPrincipal();
		//2.若登录信息中没包含权限信息，则利用1的principals来获取权限信息
		System.out.println("登录用户为："+principal);
		//3.吧权限信息封装为一个SimpleAuthorizationInfo对象，并返回
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRole("user");
		if("admin".equals(principal)){
			info.addRole("admin");
		}
		if("user".equals(principal)){
			info.addRole("tester");
		}
		
		return info;
	}
	
	/**
	 * 认证的流程：
	 * 1.在Handler中调用Subjiect的login（UsernamePasswordToken）方法
	 * 2.Shiro会回调AuthenticatingRealm实现类的doGetAuthenticationInfo方法
	 * 且doGetAuthenticationInfo方法的参数AuthenticationToken的对象即为调用Subject的login（UsernamePasswordToken）
	 * 方法时传入的参数
	 * 
	 * 关于密码加密：
	 * 1.为当前的Realm的credentialsMatcher属性，重新赋值
	 * 赋值为：新的HashedCredentialsMatcher对象，且加密算法为MD5
	 * 2.doGetAuthenticationInfo 方法的返回值为 SimpleAuthenticationInfo, 但需要使用如下的构造器:
	 * SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName)
	 * 3. 如何来计算加密后的密码 ? 
	 * Object result = new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
	 */
	//进行认证的方法
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		//1.把AuthenticationToken强转为UsernamePasswordToken
		UsernamePasswordToken upToken=(UsernamePasswordToken) token;
		
		//2.从UsernamePasswordToken中获取username，但不需要获取password
		String username = upToken.getUsername();
		
		//3.利用username调用dao方法从数据库中获取对应的用户信息
		System.out.println("利用 username:" + username + "从数据库中获取用户信息");
		if("AAA".equals(username)){
			throw new UnknownAccountException("------");
		}
		
		//4.把用户信息封装为SimpleAuthenticationInfo对象返回
		//以下信息来源于数据表
		//实际登陆用户信息，可以为username，也可以是一个实体类的对象
		String principal=username;
		//凭证信息，即密码
		String hashedCredentials=null;
		if("user".equals(username)){
			hashedCredentials = "098d2c478e9c11555ce2823231e02ec1";
		}else if("admin".equals(username)){
			hashedCredentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}
		//realm的name，只需要调用AuthorizingRealm中已经定义好的getName（）方法即可
		String realmName=getName();
		//SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, credentials, realmName);

		//若需要使用密码进行盐值加密, 则需要在参加 SimpleAuthenticationInfo 对象时
		//使用 SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName)
		//构造器. 
		//盐值: 通过调用 ByteSource.Util.bytes() 方法来生成盐值
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);
		
		SimpleAuthenticationInfo info=new SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName);
		
		return info;
	
	}
	
	//利用盐值获得密码的方法
	public static void main(String[] args) {
		String hashAlgorithmName = "MD5";
		String credentials = "123456";
		ByteSource salt = ByteSource.Util.bytes("admin");
		int hashIterations = 1024;
		Object result = new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
		
		System.out.println(result);
	}
}
