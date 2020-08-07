/**
 * 使用gate way + spring security进行token认证与动态鉴权
 *   -用户通过user-center项目的login登录时，会生成USER角色
 *     --用户动态查询tb_role_resource_authority列表，如果里面发现用户未绑定任何角色，就会绑定个USER（未存入数据库）角色，否则则会查出其绑定的角色
 *     --所有的URL访问的权限，除了白名单以外，至少需要一个USER权限进行访问，如果配置tb_role_resource_authority列表，将会把访问权限升级成列表里面的角色
 *     --超级管理员是固定的，这里默认roleId是-1（不可手动操作，改变），超级管理员可以访问所有角色
 * @Author: WuDi
 * @Description:
 * @Date: Created in 15:34 2020/8/3
 */
package test;