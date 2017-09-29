'use strict';

var ECIES = require('../');

var should = require('chai').should();
var bitcore = require('bitcore-lib-mue');
var PrivateKey = bitcore.PrivateKey;



var aliceKey = new PrivateKey('KkAfUvhooWCr3RQdaTHciTgsZV8iW6dWnJFxBffkDPfjuw2nBDTP');
var bobKey = new PrivateKey('KfX3fc12RiEZPmfidiqknJZEgd22odMgfkxeCfYgcKHZxiMZVyi7');

describe('ECIES', function() {

  it('constructor', function() {
    (typeof ECIES).should.equal('function');
  });

  it('constructs an instance', function() {
    var ecies = new ECIES();
    (ecies instanceof ECIES).should.equal(true);
  });

  it('doesnt require the "new" keyword', function() {
    var ecies = ECIES();
    (ecies instanceof ECIES).should.equal(true);
  });

  it('privateKey fails with no argument', function() {
    var ecies = ECIES();
    var fail = function() {
      ecies.privateKey();
    };
    fail.should.throw('no private key provided');
  });

  it('chainable function', function() {
    var ecies = ECIES()
      .privateKey(aliceKey)
      .publicKey(bobKey.publicKey);

    (ecies instanceof ECIES).should.equal(true);

  });

  var alice = ECIES()
    .privateKey(aliceKey)
    .publicKey(bobKey.publicKey);

  var bob = ECIES()
    .privateKey(bobKey)
    .publicKey(aliceKey.publicKey);

  var message = 'hello, to MonetaryUnit world';
  var encrypted = '0259e3da1349903aaaf3ff0d389e8086d669a9e7ae464be5b53131b590f872d96ceccc4c78c4b0b16e45f3982e4535acda1b63edfc4ebe81fd02539c4f7d720f4f206476303796e4b0d0ae247d117355fa661710dbce76d9b97ccf731040af60b1';
  var encBuf = new Buffer(encrypted, 'hex');

  it('correctly encrypts a message', function() {
    var ciphertext = alice.encrypt(message);
    Buffer.isBuffer(ciphertext).should.equal(true);
    ciphertext.toString('hex').should.equal(encrypted)
  });

  it('correctly decrypts a message', function() {
    var decrypted = bob
      .decrypt(encBuf)
      .toString();
    decrypted.should.equal(message);
  });

  it('retrieves senders publickey from the encypted buffer', function() {
    var bob2 = ECIES().privateKey(bobKey);
    var decrypted = bob2.decrypt(encBuf).toString();
    bob2._publicKey.toDER().should.deep.equal(aliceKey.publicKey.toDER());
    decrypted.should.equal(message);
  });

  it('roundtrips', function() {
    var secret = 'some secret message!!!';
    var encrypted = alice.encrypt(secret);
    var decrypted = bob
      .decrypt(encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('roundtrips (no public key)', function() {
    alice.opts.noKey = true;
    bob.opts.noKey = true;
    var secret = 'some secret message!!!';
    var encrypted = alice.encrypt(secret);
    var decrypted = bob
      .decrypt(encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('roundtrips (short tag)', function() {
    alice.opts.shortTag = true;
    bob.opts.shortTag = true;
    var secret = 'some secret message!!!';
    var encrypted = alice.encrypt(secret);
    var decrypted = bob
      .decrypt(encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('roundtrips (no public key & short tag)', function() {
    alice.opts.noKey = true;
    alice.opts.shortTag = true;
    bob.opts.noKey = true;
    bob.opts.shortTag = true;
    var secret = 'some secret message!!!';
    var encrypted = alice.encrypt(secret);
    var decrypted = bob
      .decrypt(encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('errors', function() {
    should.exist(bitcore.errors.ECIES);
  });

  it('correctly fails if trying to decrypt a bad message', function() {
    var encrypted = bitcore.util.buffer.copy(encBuf);
    encrypted[encrypted.length - 1] = 2;
    (function() { 
      return bob.decrypt(encrypted);
    }).should.throw('Invalid checksum');
  });

});
