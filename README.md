# SecurityAcl for Meteor [![Build Status](https://travis-ci.org/aumel/meteor-security-acl.svg?branch=master)](https://travis-ci.org/aumel/meteor-security-acl)

An Access Control List (ACL) security system for Meteor compatible with built-in accounts package.

It is inspired by the PHP Symfony framework.

<a name="toc">
## Table of contents

* [Installation](#installation)
* [Overview](#overview)
* [Domain object](#domain-object)
  * [Class concept in ES6](#class-concept)
  * [getDomainObjectName](#get-domain-object-name)
* [How to use the ACLs](#how-to-use-the-acls)
  * [How to use the objectAce](#how-to-use-object-ace)
  * [How to use the objectFieldAce](#how-to-use-object-field-ace)
  * [How to use the classAce](#how-to-use-class-ace)
  * [How to use the classFieldAce](#how-to-use-class-field-ace)
* [Retrieving an existing ACL](#retrieving-acl)
* [Adding a parent ACL](#adding-parent-acl)
* [How to use a role with the security identity](#how-to-use-role)
* [How to use your own user system](#how-to-use-your-own-user-system)
* [How to configure your logger](#logger)
* [How to use in the client-side](#how-to-use-client-side)
* [Advanced ACL concepts](#advanced-acl-concetps)
  * [Object identities](#object-identities)
  * [Security identities](#security-identities)
  * [Database collection structure](#database-collection-structure)
  * [Scope of ACEs](#scope-of-aces)
  * [Permissions](#permissions)
  * [Authorization decisions](#authorization-decisions)
* [Contributing](#contributing)
* [Changelog](#changelog)
* [License](#license)

<a name="installation">
## Installation

```sh
$ meteor add aumel:security-acl
```

SecurityAcl package is compatible with MongoDB and Meteor `v1.2.x`, `v1.3.x` and `v1.4.x`.

**Note:** If you are using `accounts-ui` package, you must set `passwordSignupFields` with a username

Example:
```js
Accounts.ui.config({
  passwordSignupFields: 'USERNAME_ONLY',
});
```

You can choose also choose `USERNAME_AND_EMAIL` or `USERNAME_AND_OPTIONAL_EMAIL`. For more info, read [this](http://docs.meteor.com/api/accounts.html#Accounts-ui-config)

<a name="overview">
## Overview

Sometimes in an application, the access decisions need to consider who is requesting the access (user) and also for what (domain object).

Imagine you're designing a blog application. The users can comment the posts of a blog. A user can edit his own comments but not those of the others users. The creator of a post can edit all comments of his post. In this example, you want to restrict  access to the domain object (.i.e. the collection) `Comments`.


In Meteor, the basic approaches are:

* *using business methods*: Each `comment` instance keeps a reference to all users who have access to it. To do this, you implement a collection in MongoDB with those references and the methods to retrieve informations. You can eventually use this approach with allow/deny rules.
* *using roles*: You use a role manager package and you add a role for each `comment` instance (ROLE_COMMENT_1, ROLE_COMMENT_2, ...).

Those approaches are correct. However, there are several concerns about them:

* your authorization checking is coupled with your business code.
* those approaches are inefficient and not reusable easily.
* whatever the chosen approach, you will need to write your own access control list logic from scratch.

SecurityAcl can do it in a better way.

<a name="domain-object">
## Domain object

To restrict access to an object, the SecurityAcl needs :

* the unique identifier of the object defined by `_id`.
* the unique domain object name (more informations in [Advanced ACL concepts](#advanced-acl-concetps)).

**Keep in mind that in the context of Meteor, the domain object name can be the class name of an object (ES6), the collection name of a document or the name returned by a function in the object (Model layer).**

There are two options to get the domain object name:

* using the class name from the class concept in ES6,
* implementing a `getDomainObjectName` function in the object (or document).

**Notes:**
* If SecurityAcl cannot retrieve the domain object name, an error will be thrown.
* If you use a Model layer, the ID of the object must be accessible by `object._id`. If not, an error will be thrown.

<a name="class-concept">
### Class concept in ES6

The concept of class was introduced in ES6 (ES2015). SecurityAcl supports ES6.

The class name of an object using the class concept will be automatically retrieve by SecurityAcl with `object.constructor.name`.


<a name="get-domain-object-name">
### getDomainObjectName

If the object doesn't use the class concept from ES6, it must have a function `getDomainObjectName`. This function must return an unique  *'domain name'* string.

If you want restrict access to documents, you must add the `getDomainObjectName` function to all documents using the `transform` function of `Mongo.Collection`.

```js
Posts = new Mongo.Collection("posts", {
  idGeneration: 'MONGO',
  transform: function (doc) {
    // add getDomainObjectName to all documents
    // of the collection
    doc.getDomainObjectName = function () {
      // return the unique name of the collection
      return Posts._name;
    };
    return doc;
  }
});
```
If you use a Model layer, you must extend the prototype with a `getDomainObjectName` function.

```js
Post = function (doc) {
  _.extend(this, doc);
};

Post.prototype = {
  constructor: Post,
  // add getDomainObjectName
  getDomainObjectName: function () {
    // return a unique domain name
    return 'Post';
    }
  }
};
```
<a name="how-to-use-the-acls">
## How to use the ACLs

After defining your class or adding `getDomainObjectName` function, you can implement the ACL. A domain object is represented by an object identity (more informations in [Advanced ACL concepts](#advanced-acl-concetps)). Each object identity has exactly one associated ACL. Each ACL can have four different types of Access Control Entries (class ACEs, object ACEs, class field ACEs, object field ACEs). Each ACE specifies individual user or group permissions to specific objects.

<a name="how-to-use-object-ace">
### How to use the objectAce

Access Control Entries (ACEs) can have different scopes in which they apply (more informations in [Advanced ACL concepts](#advanced-acl-concetps)). One of them is the object-scope. The entries with object-scope only apply to one specific object.


#### Creating an ACL and adding an objectAce

You create an ACL and you grant access to object by creating an Access Control Entry (ACE).

```js
Meteor.methods({
  createPost: function (text) {
    var postId = Posts.insert({
      text: text,
    });

    var post = Posts.findOne(postId);

    // creating the ACL
    var aclService = new SecurityAcl.Service();
    var acl = aclService.createAcl(SecurityAcl.objectIdentityFromDomainObject(post));

    // retrieving the security identity of the currently logged-in user
    var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());

    // you use builder for the permission mask
    var builder = new SecurityAcl.MaskBuilder();
    builder.add('owner');

    // grant owner access
    acl.insertObjectAce(securityIdentity, builder.getMask());
    aclService.updateAcl(acl);
  }
});
```
There are several important calls in this code snippet.

To manipulate (create, update, delete) an ACL, you use a `SecurityAcl.Service` instance.

The `createAcl` call doesn't accept the object directly, but only `SecurityAcl.ObjectIdentity` instance. An object is represented by an object identity to achieve a decoupling between the ACL system and the domain object.

The `insertObjectAce` call grants the logged-in user with the *OWNER* access to the `post`. Again to achieve the decoupling between the ACL system and the user domain object, the `insertObjectAce` call doesn't accept the user object but only `SecurityAcl.SecurityIdentity` instance. You retrieve the security identity with `SecurityAcl.userSecurityIdentityFromAccount`.

ACL system uses masks for permissions. A built-in builder `SecurityAcl.MaskBuilder` allows you to build cumulative permissions easily.

At the end, the `updateAcl` call persists any changes which were made to the ACL, or any associated access control entries.

**Note:** The order of ACEs is important. You should place more specific entries at the beginning.


#### Checking the access

```js
Meteor.methods({
  editPost: function (postId) {
    var post = Posts.findOne(postId);

    var authorizationChecker = new SecurityAcl.AuthorizationChecker();
    if (false === authorizationChecker.isGranted('EDIT', post)) {
      throw new Meteor.Error("not-authorized");
    }
  }
)};
```
In this code snippet, you check whether the `Meteor.user()` has the *EDIT* permission with `SecurityAcl.AuthorizationChecker` and the `isGranted` call. Internally, SecurityAcl maps the permission to several integer bitmasks, and checks whether the user has any of them.

<a name="how-to-use-object-field-ace">
### How to use an objectFieldAce

Access control entries (ACEs) can have different scopes in which they apply (more informations in [Advanced ACL concepts](#advanced-acl-concetps)). One of them is the object-field-scope. The entries with object-field-scope apply to a specific object, and only to a specific field of that object.


#### Creating an ACL and adding an objectFieldAce

Imagine you want only restrict access to the field *'title'* of a `post`. You create an ACL. You add an `objectFieldAce` to the ACL with a `insertObjectFieldAce` call specifying the field.

```js
// creating an ACL and adding an ACE
var aclService = new SecurityAcl.Service();
var acl = aclService.createAcl(SecurityAcl.objectIdentityFromDomainObject(post));

// retrieving the security identity of the currently logged-in user
var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());

// you use builder for the permission mask
var builder = new SecurityAcl.MaskBuilder();
builder.add('edit');

// grant edit access only on the 'title' field
acl.insertObjectFieldAce('title', securityIdentity, builder.getMask());
aclService.updateAcl(acl);

```

#### Checking access

To check *EDIT* permission, you create a `SecurityAcl.FieldVote` instance and call `isGranted` with it. The `SecurityAcl.FieldVote` takes two parameters, the object identity and the field.

```js
Meteor.methods({
  editTitlePost: function (postId, title) {
    var post = Posts.findOne(postId);

    // checking if logged-in user can edit 'title' of the post
    var authorizationChecker = new SecurityAcl.AuthorizationChecker();

    var oid = SecurityAcl.objectIdentityFromDomainObject(post);
    var fieldTitle = new SecurityAcl.FieldVote(oid, 'title');

    if (false === authorizationChecker.isGranted('EDIT', fieldTitle)) {
      throw new Meteor.Error("not-authorized");
    }

    Posts.update(postId, { $set: { title: title} });
  }
)};
```
<a name="how-to-use-class-ace">
### How to use a classAce

Access control entries (ACEs) can have different scopes in which they apply (more informations in [Advanced ACL concepts](#advanced-acl-concetps)). One of them is the class-scope. The entries with class-scope apply to all objects with the same domain object name.

#### Creating an ACL and adding a classAce

Imagine you want to check if a user can create a `post`. When you check the *CREATE* permission, the object instance doesn't exist yet. Fortunately, SecurityAcl allows to create ACL when you have no actual domain object instance. To do this, you create the ACL with a *class identity* (or *domain object identity*). A *class identity* is a instance of `SecurityAcl.ObjectIdentity` where the first parameter is the string *'class'* and the second one is the domain object name.

```js
// creating an ACL and adding an ACE
var aclService = new SecurityAcl.Service();

// creating an ACL applicable to all objects
// with domain object name 'posts'
var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));

// retrieving the security identity of the currently logged-in user
var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());

// you use a builder for the permission mask
var builder = new SecurityAcl.MaskBuilder();
builder.add('CREATE');

// grant owner access with classAce
acl.insertClassAce(securityIdentity, builder.getMask());
aclService.updateAcl(acl);
```

#### Checking the access

The object instance `post` doesn't exist yet. To check *CREATE* permission, you create a *class identity* and call `isGranted` with it.

```js
Meteor.methods({
  createPost: function (text) {

    // checking if logged-in user can create a post
    var authorizationChecker = new SecurityAcl.AuthorizationChecker();

    // class identity (or domain object identity)
    var postsIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

    if (false === authorizationChecker.isGranted('CREATE', postsIdentity)) {
      throw new Meteor.Error("not-authorized");
    }

    Posts.insert({
      text: text,
    });
  }
)};
```
<a name="how-to-use-class-field-ace">
### How to use a classFieldAce

Access control entries (ACEs) can have different scopes in which they apply (more informations in [Advanced ACL concepts](#advanced-acl-concetps)). One of them is the class-field-scope. The entries with class-field-scope apply to all objects with the same domain object name, but only to a specific field of the objects.

#### Creating an ACL and adding an classFieldAce

Imagine you want only restrict access to the field *'title'* of all instances of `Posts`. You create an ACL with a *'class identity'*. A *'class identity'* is a instance of `SecurityAcl.ObjectIdentity` where the first parameter is a string *'class'*. You add an `classFieldAce` to the ACL with a `insertClassFieldAce` call specifying the field.

```js
// creating an ACL and adding an ACE
var aclService = new SecurityAcl.Service();
var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));

// retrieving the security identity of the currently logged-in user
var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());

// you use builder for the permission mask
var builder = new SecurityAcl.MaskBuilder();
builder.add('edit');

// grant edit access only on the 'title' field
acl.insertClassFieldAce('title', securityIdentity, builder.getMask());
aclService.updateAcl(acl);
```

#### Checking the access

The object instance `post` doesn't exist yet. To check *EDIT* permission, you create a `SecurityAcl.FieldVote` instance with a *class identity* and call `isGranted` with it. The `SecurityAcl.FieldVote` takes two parameters, the *class identity* and the field.

```js
Meteor.methods({
  editTitlePost: function (title) {

    // checking if logged-in user can create a post
    var authorizationChecker = new SecurityAcl.AuthorizationChecker();

    // class identity (or domain object identity)
    var postsIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
    var fieldTitle = new SecurityAcl.FieldVote(postIdentity, 'title');

    if (false === authorizationChecker.isGranted('EDIT', fieldTitle)) {
      throw new Meteor.Error("not-authorized");
    }

    Posts.update(postId, { $set: { title: title} });
  }
)};
```

<a name="retrieving-acl">
## Retrieving an existing ACL

You can retrieve an existing ACL with the `findACl` call. You need the object identity of your domain object to retrieve the corresponding ACL.

```js
var oid = SecurityAcl.objectIdentityFromDomainObject(post)
// retrieve an existing ACL
var acl = aclService.findAcl(oid);
```
<a name="adding-parent-acl">
## Adding a parent ACL

Coming back to our first example, imagine the creator of a post can view/edit/delete all comments of his post. In other words, the creator has the same permissions on the comments than on his post. To do this, you can use the inheritance capacity of SecurityAcl. An ACL can inherit from a parent ACL.

```js
// imagine you have an existing ACL for the post
var oid = SecurityAcl.objectIdentityFromDomainObject(post)
// retrieve an existing ACL
var postAcl = aclService.findAcl(oid);

// the creator of the post can do anything on the comments of his post.
var aclService = new SecurityAcl.Service();
var acl = aclService.createAcl(SecurityAcl.objectIdentityFromDomainObject(comment));

// when you are creating the ACL for a comment, you set the parent ACL.
acl.setParentAcl(postAcl);

aclService.updateAcl(acl);


```

<a name="how-to-use-role">
## How to use a role with the security identity

First, your role system must respect some rules:

* The user instance must have a roles property (i.e. `user.roles`).
* The `user.roles` can be an array (e.g. `['moderator', 'member']`).
* The `user.roles` can be an object literal (e.g. `{ 'tech-blog' : ['moderator'] }`).

**Note:** SecurityAcl is compatible with the `alanning:roles` package.

### Creating ACL and adding ACE

Imagine, you have a role system and you want users with a *moderator* role can edit all comments. SecurityAcl can manage the roles with `RoleSecurityIdentity`.

```js
// creating an ACL with a class identity.
var aclService = new SecurityAcl.Service();
var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'comments'));

// retrieving the role security identity
var securityIdentity = new SecurityAcl.RoleSecurityIdentity('moderator');

// you use a builder for the permission mask
var builder = new SecurityAcl.MaskBuilder();
builder.add('OPERATOR');

// grant operator access with classAce
acl.insertClassAce(securityIdentity, builder.getMask());
aclService.updateAcl(acl);
```

If you use a role with an object literal (e.g. `{ 'tech-blog' : ['moderator'] }`), you must define `SecurityAcl.RoleSecurityIdentity` with the name of property, followed by a symbol `-` and the role.

```js
// creating an ACL with a class identity.
var aclService = new SecurityAcl.Service();
var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'comments'));

// defining the role security identity for an object literal
var securityIdentity = new SecurityAcl.RoleSecurityIdentity('tech-blog-moderator');

// you use a builder for the permission mask
var builder = new SecurityAcl.MaskBuilder();
builder.add('OPERATOR');

// grant operator access with classAce
acl.insertClassAce(securityIdentity, builder.getMask());
aclService.updateAcl(acl);
```

### Checking access


The SecurityAcl manages automatically the role. it checks whether the user has the required role to access to the domain object.

```js
// checking if logged-in user can edit a comment
var authorizationChecker = new SecurityAcl.AuthorizationChecker();

// class identity (or domain object identity)
var commentsIdentity = new SecurityAcl.ObjectIdentity('class', 'comments');

if (false === authorizationChecker.isGranted('EDIT', commentsIdentity)) {
  throw new Meteor.Error("not-authorized");
}
```

<a name="how-to-use-your-own-user-system">
## How to use your own user system

If you don't use the built-in accounts package of Meteor or if you use a Model layer over the `Meteor.user()`, SecurityAcl provides a solution to hold those situations.

Imagine you have your own users system and you want to create an ACL with it. You can use your user instance with `userSecurityIdentityFromAccount` to get your security identity.

```js
// creating the ACL
var aclService = new SecurityAcl.Service();
var acl = aclService.createAcl(SecurityAcl.objectIdentityFromDomainObject(post));

// retrieving the security identity from our own user implementation
var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(user);

// you use builder for the permission mask
var builder = new SecurityAcl.MaskBuilder();
builder.add('owner');

// grant owner access
acl.insertObjectAce(securityIdentity, builder.getMask());
aclService.updateAcl(acl);
```
Your user instance must respect some rules:

* The user instance must have a username property (i.e. `user.username`).
* The user instance must use the class concept or must have a `getDomainObjectName` function.

When you want check the access with `SecurityAcl.AuthorizationChecker`, you must set the authenticated user manually with `setAuthenticatedUser`.

```js
// ...
var authorizationChecker = new SecurityAcl.AuthorizationChecker();
// add manually your authenticated user.
var authorizationChecker.setAuthenticatedUser(user);

if (false === authorizationChecker.isGranted('EDIT', post)) {
  throw new Meteor.Error("not-authorized");
}

// ...
```
<a name="logger">
## How to configure your logger

If you use a logger to detail the debug informations, you can configure it with the `SecurityAcl.setLogger` call. Your logger must have a debug function `logger.debug()` otherwise an error will be thrown.

```js
// ...
SecurityAcl.setLogger(yourLogger);
// ...
```

**Note:** Actually, the logger reports debug messages about authorization decisions.

<a name="how-to-use-client-side">
## How to use in the client-side

As the server-side, the client-side has access to all functions of SecurityAcl. It is eventually useful for creating helpers.

**IMPORTANT:** The access to sensitive data must always be controlled on the server-side. Any client-side helpers cannot be trusted. Those helpers can be used for accessing to some templates if the access to data is restricted to the server-side.

<a name="advanced-acl-concetps">
## Advanced ACL concepts

SecurityAcl is based on the concept of an access control list (ACL). Every domain object instance in your application has exactly one associated ACL. An ACL defines who can and can't work with that domain object.

<a name="object-identities">
### Object identities

The SecurityAcl is totally decoupled from your domain objects. To achieve this decoupling, each domain object is represented internally within the SecurityAcl by an object identity.

<a name="security-identities">
### Security identities

In the same way as a domain object is represented by an object identity, a user and a role are represented by a security identity.

<a name="database-collection-structure">
### Database collection structure

There are five main collections used by default in the implementation. The collections are ordered from least documents to most documents in a typical application:

* *acl_security_identities*: This collection contains all security identities (SID) which hold ACEs. There are two types of security identities: `RoleSecurityIdentity` and `UserSecurityIdentity`.
* *acl_classes*: This collection maps class names (object domaine names) to a unique ID which can be referenced from other collections.
* *acl_object_identities*: Each document in this collection represents a single domain object instance (or *class identity*).
* *acl_object_identity_ancestors*: This collection allows all the ancestors of an ACL to be determined in a very efficient way.
* *acl_entries*: This collection contains all ACEs.

<a name="scope-of-aces">
### Scope of ACEs

Access control entries (ACEs) can have different scopes in which they apply. There are four scopes:

* *object-scope*: The entries with object-scope only apply to one specific object.
* *object-field-scope*: The entries with object-field-scope apply to a specific object, and only to a specific field of that object.
* *class-scope*: The entries with class-scope apply to all objects with the same domain object name.
* *class-field-scope*: The entries with class-field-scope apply to all objects with the same domain object name, but only to a specific field of the objects.

<a name="permissions">
### Permissions

SecurityAcl uses integer bit masking. You don't need to know anything about bits shifting to use SecurityAcl.

Keep just in mind:

* A permission is defined by an integer bitmask.
* You can define up to 31 base permissions (in JavaScript, bitwise operators and shift operators operate on 32-bit ints and the limit is 2^32-1).
* You can also define cumulative permissions named *attributes*. These *attributes* represent in fact an aggregate of integer bitmasks.



#### Integer Bitmasks

The built-in integer bitmasks used by SecurityAcl.

| Permission       | Mask         |
|------------------|--------------|
|VIEW | 1 |
|CREATE | 2 |
|EDIT | 4 |
|DELETE | 8 |
|UNDELETE | 16 |
|OPERATOR | 32 |
|MASTER | 64 |
|OWNER | 128 |


#### Permission Map

The built-in permission map used by SecurityAcl.

| Attribute        | Meaning           | Integer Bitmasks            |
|------------------|----------------------------|-----------------------------|
| VIEW             | The SID is allowed to view the domain object / field. | VIEW, EDIT, OPERATOR, MASTER, or OWNER     |
| EDIT             | The SID is allowed to edit existing instances of the domain object / field. | EDIT, OPERATOR, MASTER, or OWNER   |
| CREATE           | The SID is allowed to create new instances of the domain object / fields. | CREATE, OPERATOR, MASTER, or OWNER  |
| DELETE           | The SID is allowed to delete domain objects. | DELETE, OPERATOR, MASTER, or OWNER    |
| UNDELETE         | The SID is allowed to restore a previously deleted domain object. | UNDELETE, OPERATOR, MASTER, or OWNER |
| OPERATOR         | The SID is allowed to perform any action on the domain object except for granting others permissions. | OPERATOR, MASTER, or OWNER  |
| MASTER           | The SID is allowed to perform any action on the domain object, and is allowed to grant other SIDs any permission except for MASTER and OWNER permissions. | MASTER, or OWNER            |
| OWNER            | The SID is owning the domain object in question and can perform any action on the domain object as well as grant any permission. | OWNER                       |

**Note:** This permission map can be replaced by another but it covers lot of situations.

<a name="authorization-decisions">
### Authorization decisions

The authorizationChecker provides a function `isGranted` for determining whether the user has the required attributes to access to the domain object. Behind this function, a mechanism of voter with an affirmative strategy is used to determine if the access is granted. The voter `SecurityAcl.AclVoter` votes to allow or to deny access using the `SecurityAcl.Acl.isGranted` and `SecurityAcl.Acl.isFieldGranted` calls. Those two functions determine whether a security identity has the required bitmasks. The `isGranted` and `isFieldGranted` calls delegate the request to a `SecurityAcl.PermissionGrantingStrategy`.

The `SecurityAcl.PermissionGrantingStrategy` checks all your object-scope ACEs. If none is applicable, the class-scope ACEs will be checked. If none is applicable, then the process will be repeated with the ACEs of the parent ACL. If no parent ACL exists, an error will be thrown.


<a name="contributing">
## Contributing

Please make sure to read the [Contributing Guide](CONTRIBUTING.md) before making a pull request.

<a name="changelog">
## Changelog

Details changes for each release are documented in the [CHANGELOG file](CHANGELOG.md).

<a name="License">
## License

SecurityAcl is released under the [MIT License](LICENSE).
