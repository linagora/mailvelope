/**
 * Mailvelope - secure email with OpenPGP encryption for Webmail
 * Copyright (C) 2015 Mailvelope GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

'use strict';

define(function(require, exports, module) {

  var mvelo = require('../lib-mvelo').mvelo;
  var indexedDB = mvelo.storage.indexedDB;
  var openpgp = require('openpgp');

  var DB_NAME = 'mailvelope';
  var DB_VERSION = 1;
  var DB_STORE_KEYS = 'keys';
  var DB_STORE_KEYRING_ATTR = 'keyring-attributes';

  var db;

  function init() {
    return openDb();
  }

  function openDb() {
    console.log('openDb');
    return new Promise(function(resolve, reject) {
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onsuccess = function() {
        db = this.result;
        console.log('indexedDB.open success');
        resolve();
      };
      req.onerror = function(event) {
        console.error('indexedDB.open error', event.target.errorCode);
        reject();
      };
      req.onupgradeneeded = upgradeDb;
    });
  }

  function upgradeDb(event) {
    switch (event.newVersion) {
      case 1:
        upgradeDbToV1(event.target.result);
        break;
      default:
        throw new Error('No upgrade path for indexedDB version');
    }
  }

  function addKeysToStore(keyringId, keys, type, store) {
    keys.forEach(function(armored) {
      try {
        var key = openpgp.key.readArmored(armored).keys[0];
        store.add({
          armored: armored,
          keyringId: keyringId,
          fingerprint: key.primaryKey.getFingerprint(),
          type: type
        });
      } catch (e) {
        console.log('Could not migrate key:', key);
      }
    });
  }

  function upgradeDbToV1(db) {
    console.log('openDb.onupgradeneeded version 1');
    db.createObjectStore(DB_STORE_KEYRING_ATTR, { keyPath: 'keyringId' })
      .transaction.oncomplete = function() {
        var keyStore = db.createObjectStore(DB_STORE_KEYS, { autoIncrement: true });
        keyStore.createIndex('keyringId', 'keyringId', { unique: false });
        keyStore.createIndex('fingerprint', 'fingerprint', { unique: false });
        keyStore.createIndex('type', 'type', { unique: false });
        keyStore.transaction.oncomplete = function() {
          var transaction = db.transaction([DB_STORE_KEYRING_ATTR, DB_STORE_KEYS], "readwrite");
          transaction.oncomplete = function() {
            console.log('keys and keyring attributes written to db');
          };
          var keyringAttrStore = transaction.objectStore(DB_STORE_KEYRING_ATTR);
          var keyStore = transaction.objectStore(DB_STORE_KEYS);
          var keyringAttr = mvelo.storage.get('mailvelopeKeyringAttr');
          var pubKeys, privKeys;
          if (keyringAttr && keyringAttr[mvelo.LOCAL_KEYRING_ID]) {
            for (var keyringId in keyringAttr) {
              keyringAttrStore.add({
                keyringId: keyringId,
                primaryKeyId: keyringAttr[keyringId].primary_key
              });
              if (keyringId === mvelo.LOCAL_KEYRING_ID) {
                pubKeys = mvelo.storage.get('openpgp-public-keys');
                privKeys = mvelo.storage.get('openpgp-private-keys');
              } else {
                pubKeys = mvelo.storage.get(keyringId + 'public-keys');
                privKeys = mvelo.storage.get(keyringId + 'private-keys');
              }
              addKeysToStore(keyringId, pubKeys, 'public', keyStore);
              addKeysToStore(keyringId, privKeys, 'private', keyStore);
            }
          } else {
            keyringAttrStore.add({
              keyringId: mvelo.LOCAL_KEYRING_ID,
              primaryKeyId: mvelo.storage.get('mailvelopePreferences').general.primary_key
            });
            pubKeys = mvelo.storage.get('openpgp-public-keys');
            privKeys = mvelo.storage.get('openpgp-private-keys');
            addKeysToStore(mvelo.LOCAL_KEYRING_ID, pubKeys, 'public', keyStore);
            addKeysToStore(mvelo.LOCAL_KEYRING_ID, privKeys, 'private', keyStore);
          }
          console.log('keyringStore ready');
        };

      };
  }

  exports.init = init;

});
