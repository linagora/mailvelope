/**
 * Mailvelope - secure email with OpenPGP encryption for Webmail
 * Copyright (C) 2012  Thomas Oberndörfer
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

var mvelo = mvelo || null;

(function() {
  // communication to background page
  var port;
  // shares ID with DecryptFrame
  var id;
  var name;
  var watermark;
  //var spinnerTimer;
  var commonPath;
  var l10n;

  function init() {
    //console.log('init decryptInline.js');
    var qs = jQuery.parseQuerystring();
    id = qs.id;
    name = 'dDialog-' + id;
    // open port to background page
    port = mvelo.extension.connect({name: name});
    port.onMessage.addListener(messageListener);
    port.postMessage({event: 'decrypt-inline-init', sender: name});
    if (mvelo.crx) {
      commonPath = '../../..';
    } else if (mvelo.ffa) {
      commonPath = mvelo.extension._dataPath + 'common';
    }
    addSpinner();
    addAttachmentPanel();
    addWrapper();
    addSandbox();
    addSecuritySettingsButton();
    $(window).on('resize', resizeFont);
    addErrorView();
    // show spinner
    mvelo.l10n.getMessages([
      'alert_header_error'
    ], function(result) {
      l10n = result;
    });
    mvelo.util.showSecurityBackground(true);
    mvelo.l10n.localizeHTML();
  }

  function addSpinner() {
    var spinner = $('<div class="m-spinner"><div class="bounce1"></div><div class="bounce2"></div><div class="bounce3"></div></div>');
    spinner.appendTo('body');
  }

  function showSpinner() {
    $(".m-spinner").show();
  }

  function hideSpinner() {
    $(".m-spinner").hide();
  }

  function addWrapper() {
    var wrapper = $('<div/>', {id: 'wrapper'});
    watermark = $('<div/>', {id: 'watermark'});
    watermark.appendTo(wrapper);
    wrapper.appendTo('body');
  }

  function addAttachmentPanel() {
    var attachments = $('<div/>', {
      id: 'attachments'
    });
    $('body').append(attachments);
  }

  function addSecuritySettingsButton() {
    var securitySettingsBtn = $('<div id="footer"><button class="btn btn-link pull-right secureBgndSettingsBtn" style="margin-right: 7px; margin-bottom: 7px;" data-l10n-title-id="security_background_button_title"><span class="glyphicon lockBtnIcon"></span></button></div>');
    $('body').append(securitySettingsBtn);

    $(".secureBgndSettingsBtn").on("click", function() {
      port.postMessage({ event: 'open-security-settings', sender: name });
    });
  }

  function addSandbox() {
    var sandbox = $('<iframe/>', {
      id: 'decryptmail',
      sandbox: 'allow-same-origin allow-popups',
      frameBorder: 0
    });
    var content = $('<div/>', {
      id: 'content',
      css: {
        position: 'absolute',
        top: '0',
        left: 0,
        right: 0,
        bottom: 0,
        padding: '3px',
        //'margin-top': '40px',
        'background-color': 'rgba(0,0,0,0)',
        overflow: 'auto'
      }
    });
    var style = $('<link/>', {
      rel: 'stylesheet',
      href: commonPath + '/dep/bootstrap/css/bootstrap.css'
    });
    var meta = $('<meta/>', { charset: 'UTF-8' });
    sandbox.on('load', function() {
      $(this).contents().find('head').append(meta)
                                     .append(style);
      $(this).contents().find('body').css('background-color', 'rgba(0,0,0,0)');
      $(this).contents().find('body').append(content);
    });
    content.on('mouseup', function(event) {
      // exception due to sandbox
      //logUserInput('CONTENT_MOUSEUP');
    });
    $('#wrapper').append(sandbox);
  }

  function addErrorView() {
    var errorbox = $('<div/>', {id: 'errorbox'});
    $('<div/>', {id: 'errorwell', class: 'well span5'}).appendTo(errorbox);
    errorbox.appendTo('body');
    if ($('body').height() + 2 > mvelo.LARGE_FRAME) {
      $('#errorbox').addClass('errorbox-large');
    }
  }

  function showMessageArea() {
    $('html, body').addClass('hide_bg');
    hideSpinner();
    $('#wrapper').addClass('fade-in');
    resizeFont();
  }

  function showErrorMsg(msg) {
    hideSpinner();
    //clearTimeout(spinnerTimer);
    $('#errorbox').show();
    $('#errorwell').showAlert(l10n.alert_header_error, msg, 'danger')
                   .find('.alert').prepend($('<button/>', {type: 'button', class: 'close', html: '&times;'}))
                   .find('button').click(function() {
                      port.postMessage({event: 'decrypt-dialog-cancel', sender: name});
                    });
  }

  function resizeFont() {
    watermark.css('font-size', Math.floor(Math.min(watermark.width() / 3, watermark.height())));
  }

  function addAttachment(filename, content, mimeType, attachmentId) {
    var fileNameNoExt = mvelo.util.extractFileNameWithoutExt(filename);
    var fileExt = mvelo.util.extractFileExtension(filename);
    var extClass = mvelo.util.getExtensionClass(fileExt);

    var $extensionButton = $('<span/>', {
      "class": 'label attachmentExtension ' + extClass
    }).append(fileExt);

    var objectURL = "#";

    var contentLength = Object.keys(content).length;
    var uint8Array = new Uint8Array(contentLength);
    for (var i = 0; i < contentLength; i++) {
      uint8Array[i] = content[i];
    }
    var blob = new Blob([uint8Array], { type: mimeType });
    objectURL = window.URL.createObjectURL(blob);

    var $fileName = $('<span/>', {
      "class": 'filename'
    }).append(fileNameNoExt);

    var $fileUI = $('<a/>', {
        "download": filename,
        "href": objectURL,
        "title": filename,
        "class": 'attachmentButton'
      })
        .append($extensionButton)
        .append($fileName);

    if (mvelo.ffa && mvelo.getFirefoxVersion() < 36) {
      $fileUI.on("click", function(e) {
        e.preventDefault();
        port.postMessage({event: 'get-attachment', sender: name, attachmentId: attachmentId});
      });
    }

    $fileUI.on("click", function() {
      logUserInput('security_log_attachment_download');
    });

    $('#attachments').append($fileUI);
  }

  function logUserInput(type) {
    port.postMessage({
      event: 'decrypt-inline-user-input',
      sender: name,
      source: 'security_log_email_viewer',
      type: type
    });
  }

  function messageListener(msg) {
    //console.log('decrypt dialog messageListener: ', JSON.stringify(msg));
    switch (msg.event) {
      case 'decrypted-message':
        showMessageArea();
        // js execution is prevented by Content Security Policy directive: "script-src 'self' chrome-extension-resource:"
        msg.message = $.parseHTML(msg.message);
        $('#decryptmail').contents().find('#content').append(msg.message);
        hideSpinner();
        $('body').addClass('secureBackground');
        break;
      case 'add-decrypted-attachment':
        //console.log('popup adding decrypted attachment: ', JSON.stringify(msg.message));
        showMessageArea();
        addAttachment(msg.message.filename, msg.message.content, msg.message.mimeType, msg.message.attachmentId);
        break;
      case 'error-message':
        showErrorMsg(msg.error);
        break;
      default:
        console.log('unknown event');
    }
  }

  $(document).ready(init);

}());
