package com.atguigu.shiro;

import org.apache.shiro.authz.annotation.RequiresRoles;

public class MyService {
	
	/**
	 * 使用 shiro 的注解可以来完成最细粒度的权限控制
	 */
	@RequiresRoles("tester")
	public void test(){
		System.out.println("test....");
	}
	
}
