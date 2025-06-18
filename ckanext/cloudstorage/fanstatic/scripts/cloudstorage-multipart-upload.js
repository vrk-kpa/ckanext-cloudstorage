ckan.module('cloudstorage-multipart-upload', function($, _) {
    'use strict';

    return {
        options: {
            cloud: 'S3',
            i18n: {
                resource_create: _('Resource has been created.'),
                resource_update: _('Resource has been updated.'),
                undefined_upload_id: _('Undefined uploadId.'),
                upload_completed: _('Upload completed. You will be redirected in few seconds...'),
                unable_to_finish: _('Unable to finish multipart upload')
            }
        },

        _partNumber: 1,

        _uploadId: null,
        _packageId: null,
        _resourceId: null,
        _uploadSize: null,
        _uploadName: null,
        _uploadedParts: null,
        _clickedBtn: null,
        _redirect_url: null,

        initialize: function() {
            $.proxyAll(this, /_on/);
            this.options.packageId = this.options.packageId.slice(1);
            this._form = this.$('form');
            // this._origin = $('#field-image-upload');
            // this._file = this._origin.clone()
            this._file = $('#field-image-upload, #field-resource-upload');
            this._url = $('#field-image-url, #field-resource-url');
            this._save = $('[name=save]');
            this._id = $('input[name=id]');
            this._progress = $('<div>', {
                class: 'progress hidden'
            });
            this._bar = $('<div>', {
                class: 'progress-bar progress-bar-striped active'
            });
            this._progress.append(this._bar);
            this._progress.insertAfter(this._url.parent().parent());
            this._resumeBtn = $('<a>', {class: 'hidden btn btn-info controls'}).insertAfter(
                this._progress).text('Resume Upload');
            this._pressedSaveButton = null;

            var self = this;
            var csrf_field = $("meta[name=csrf_field_name]").attr("content");
            this._frm_csrf_token = $("meta[name=" + csrf_field + "]").attr("content");

            this._file.fileupload({
                url: this.sandbox.client.url('/api/action/cloudstorage_upload_multipart'),
                maxChunkSize: 5 * 1024 * 1024,
                replaceFileInput: false,
                formData: this._onGenerateAdditionalData,
                submit: this._onUploadFileSubmit,
                chunkdone: this._onChunkUploaded,
                add: this._onFileUploadAdd,
                progressall: this._onFileUploadProgress,
                done: this._onFinishUpload,
                fail: this._onUploadFail,
                always: this._onAnyEndedUpload,
                headers: {
                    "X-CSRFToken": this._frm_csrf_token,
                },
            });

            this._save.on('click', this._onSaveClick);

            this._onCheckExistingMultipart('choose');
        },

        _onChunkUploaded: function () {
            this._uploadedParts = this._partNumber++;
        },

        _onCheckExistingMultipart: function (operation) {
            var self = this;
            var id = this._id.val();
            if (!id) return;
            this.sandbox.client.call(
                'POST',
                'cloudstorage_check_multipart',
                {id: id},
                function (data) {
                    if (!data.result) return;
                    var upload = data.result.upload;

                    var name = upload.name.slice(upload.name.lastIndexOf('/')+1);
                    self._uploadId = upload.id;
                    self._uploadSize = upload.size;
                    self._uploadedParts = upload.parts;
                    self._uploadName = upload.original_name;
                    self._partNumber = self._uploadedParts + 1;


                    var current_chunk_size = self._file.fileupload('option', 'maxChunkSize');
                    var uploaded_bytes = current_chunk_size * upload.parts;
                    self._file.fileupload('option', 'uploadedBytes', uploaded_bytes);

                    self.sandbox.notify(
                        'Incomplete upload',
                        'File: ' + upload.original_name +
                             '; Size: ' + self._uploadSize,
                        'warning');
                    self._onEnableResumeBtn(operation);
                },
                function (error) {
                    console.log(error);
                    setTimeout(function() {
                        self._onCheckExistingMultipart(operation);
                    }, 2000);
                }

            );
        },

        _onEnableResumeBtn: function (operation) {
            var self = this;
            this.$('.btn-remove-url').remove();
            if (operation === 'choose'){
                self._onDisableSave(true);

            }
            this._resumeBtn
                .off('click')
                .on('click', function (event) {
                    switch (operation) {
                    case 'resume':
                        self._save.trigger('click');
                        self._onDisableResumeBtn();
                        break;
                    case 'choose':
                    default:
                        self._file.trigger('click');
                        break;
                    }
                })
                .removeClass('hidden').show();
        },

        _onDisableResumeBtn: function () {
            this._resumeBtn.hide();
        },

        _onUploadFail: function (e, data) {
            this._onHandleError('Upload fail');
            this._onCheckExistingMultipart('resume');
        },

        _onUploadFileSubmit: function (event, data) {
            if (!this._uploadId) {
                this._onDisableSave(false);
                this.sandbox.notify(
                    'Upload error',
                    this.i18n('undefined_upload_id'),
                    'error'
                );
                return false;
            }

            this._setProgressType('info', this._progress);
            this._progress.removeClass('hidden').show('slow');
        },

        _onGenerateAdditionalData: function (form) {
            return [
                {
                    name: 'partNumber',
                    value: this._partNumber
                },
                {
                    name: 'uploadId',
                    value: this._uploadId
                },
                {
                    name: 'id',
                    value: this._resourceId
                }

            ];
        },

        _onAnyEndedUpload: function () {
            this._partNumber = 1;
        },

        _countChunkSize: function (size, chunk) {
            while (size / chunk > 10000) chunk *= 2;
            return chunk;
        },

        _onFileUploadAdd: function (event, data) {
            this._setProgress(0, this._bar);
            var file = data.files[0];
            var target = $(event.target);

            var chunkSize = this._countChunkSize(file.size, target.fileupload('option', 'maxChunkSize'));

            if (this._uploadName && this._uploadSize && this._uploadedParts !== null) {
                if (this._uploadSize !== file.size || this._uploadName !== file.name){
                    this._file.val('');
                    this._onCleanUpload();
                    this.sandbox.notify(
                        'Mismatch file',
                        'You are trying to upload wrong file. Cancel previous upload first.',
                        'error'
                    );
                    event.preventDefault();
                    throw 'Wrong file';
                }


                var loaded = chunkSize * this._uploadedParts;

                // target.fileupload('option', 'uploadedBytes', loaded);
                this._onFileUploadProgress(event, {
                    total: file.size,
                    loaded: loaded
                });

                this._progress.removeClass('hidden').show('slow');
                this._onDisableResumeBtn();
                this._save.trigger('click');

                if (loaded >= file.size){
                    this._onFinishUpload();
                }

            }


            target.fileupload('option', 'maxChunkSize', chunkSize);

            this.el.off('multipartstarted.cloudstorage');
            this.el.on('multipartstarted.cloudstorage', function () {
                data.submit();
            });
        },

        _onFileUploadProgress: function (event, data) {
            var progress = 100 / (data.total / data.loaded);
            this._setProgress(progress, this._bar);
        },

        _onSaveClick: function(event, pass) {
            if (pass || !window.FileList || !this._file || !this._file.val()) {
                return;
            }
            event.preventDefault();

            try{
                this._onDisableSave(true);
                this._pressedSaveButton = $(event.target).attr('value');
                this._onSaveForm();
            } catch(error){
                console.log(error);
                this._onDisableSave(false);
            }
        },

        _onSaveForm: function() {
            var file = this._file[0].files[0];
            var self = this;
            var formData = this._form.serializeArray().reduce(
                function (result, item) {
                    result[item.name] = item.value;
                    return result;
            }, {});

            formData.multipart_name = file.name;
            formData.url = file.name;
            formData.package_id = this.options.packageId;
            formData.size = file.size;
            formData.url_type = 'upload';
            var action = formData.id ? 'resource_update' : 'resource_create';
            var url = this._form.attr('action') || window.location.href;
            this.sandbox.client.call(
                'POST',
                action,
                formData,
                function (data) {
                    var result = data.result;
                    self._packageId = result.package_id;
                    self._resourceId = result.id;

                    self._id.val(result.id);
                    self.sandbox.notify(
                        result.id,
                        self.i18n(action, {id: result.id}),
                        'success'
                    );
                    self._onPerformUpload(file);
                },
                function (err, st, msg) {

                  if ( err.responseJSON.error !== null){
                    for (const prop in err.responseJSON.error){
                      if (prop !== '__type') {
                        self.sandbox.notify(
                          'Error',
                          `${prop}: ${err.responseJSON.error[prop][0]}`,
                          'error'
                        );
                      }
                    }
                  }
                  else{
                    self.sandbox.notify(
                      'Error',
                      msg,
                      'error'
                    );
                  }
                    self._onHandleError('Unable to save resource');
                }
            );

        },


        _onPerformUpload: function(file) {
            var id = this._id.val();
            var self = this;
            if (this._uploadId === null)
                this._onPrepareUpload(file, id, this._frm_csrf_token).then(
                    function (data) {
                        self._uploadId = data.result.id;
                        self.el.trigger('multipartstarted.cloudstorage');
                    },
                    function (err) {
                        console.log(err);
                        self._onHandleError('Unable to initiate multipart upload');
                    }
                );
            else
                this.el.trigger('multipartstarted.cloudstorage');

        },

        _onPrepareUpload: function(file, id, csrf) {

            return $.ajax({
                method: 'POST',
                url: this.sandbox.client.url('/api/action/cloudstorage_initiate_multipart'),
                data: JSON.stringify({
                    id: id,
                    name: encodeURIComponent(file.name),
                    size: file.size
                }),
                headers: {
                    "X-CSRFToken": csrf,
                },
            });

        },

        _onAbortUpload: function(id) {
            var self = this;
            this.sandbox.client.call(
                'POST',
                'cloudstorage_abort_multipart',
                {
                    id: id
                },
                function (data) {
                    console.log(data);
                },
                function (err) {
                    console.log(err);
                    self._onHandleError('Unable to abort multipart upload');
                }
            );

        },

        _onFinishUpload: function() {
            var self = this;
            var keepDraft = this._pressedSaveButton == 'again' || this._pressedSaveButton == 'go-dataset';
            let ref_client = this.sandbox.client;
            this.sandbox.client.call(
                'POST',
                'cloudstorage_finish_multipart',
                {
                    'uploadId': this._uploadId,
                    'id': this._resourceId,
                    'keepDraft': keepDraft,
                    'save_action': this._pressedSaveButton
                },
                function (data) {

                    self._progress.hide('fast');
                    self._onDisableSave(false);

                    if (self._resourceId && self._packageId){
                        self.sandbox.notify(
                            'Success',
                            self.i18n('upload_completed'),
                            'success'
                        );

                        let package_type = 'dataset' //Default type 
                        // Get the package type 
                        ref_client.call(
                            'POST',
                            'package_show',
                            {
                                'id': self._packageId
                            },
                            function (data){
                                try {
                                    // try to parse type from the results
                                    package_type = data.result.type;
                                }
                                catch (error) {
                                    console.log(error);
                                }
                                // self._form.remove();
                                if (self._pressedSaveButton == 'again') {
                                    var path = `/${package_type}/new_resource/`;
                                } else if (self._pressedSaveButton == 'go-dataset') {
                                    var path = `/${package_type}/edit/`;
                                } else {
                                    var path = `/${package_type}/`;
                                }
                                var redirect_url = self.sandbox.url(path + self._packageId);

                                self._form.attr('action', redirect_url);
                                self._form.attr('method', 'GET');
                                self.$('[name]').attr('name', null);
                                setTimeout(function(){
                                    self._form.submit();
                                }, 3000);

                            },
                            function (error){
                                console.log(error);
                            }
                        );
                    }
                },
                function (err) {
                    console.log(err);
                    self._onHandleError(self.i18n('unable_to_finish'));
                }
            );
            this._setProgressType('success', this._progress);
        },

        _onDisableSave: function (value) {
            this._save.attr('disabled', value);
        },

        _setProgress: function (progress, bar) {
            bar.css('width', progress + '%').text(Math.round(progress) + '%');
        },

        _setProgressType: function (type, progress) {
            progress
                .removeClass('progress-success progress-danger progress-info')
                .addClass('progress-' + type);
        },

        _onHandleError: function (msg) {
            this.sandbox.notify(
                'Error',
                msg,
                'error'
            );
            this._onDisableSave(false);
        },

        _onCleanUpload: function () {
            this.$('.btn-remove-url').trigger('click');
        }

    };
});
