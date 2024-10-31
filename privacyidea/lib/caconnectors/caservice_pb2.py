# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: caservice.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0f\x63\x61service.proto\"\'\n\x06Status\x12\x0c\n\x04\x63ode\x18\x01 \x01(\x05\x12\x0f\n\x07message\x18\x02 \x01(\t\";\n\x10SetOptionRequest\x12\x12\n\noptionName\x18\x01 \x01(\t\x12\x13\n\x0boptionValue\x18\x02 \x01(\t\")\n\x0eSetOptionReply\x12\x17\n\x06status\x18\x01 \x01(\x0b\x32\x07.Status\"\x13\n\x11GetOptionsRequest\"\x8a\x01\n\x0fGetOptionsReply\x12.\n\x07options\x18\x01 \x03(\x0b\x32\x1d.GetOptionsReply.OptionsEntry\x12\x17\n\x06status\x18\x02 \x01(\x0b\x32\x07.Status\x1a.\n\x0cOptionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"E\n\x10SubmitCSRRequest\x12\x0b\n\x03\x63sr\x18\x01 \x01(\t\x12\x14\n\x0ctemplateName\x18\x02 \x01(\t\x12\x0e\n\x06\x63\x61Name\x18\x03 \x01(\t\"m\n\x0eSubmitCSRReply\x12\x13\n\x0b\x64isposition\x18\x01 \x01(\x05\x12\x1a\n\x12\x64ispositionMessage\x18\x02 \x01(\t\x12\x11\n\trequestId\x18\x03 \x01(\x05\x12\x17\n\x06status\x18\x05 \x01(\x0b\x32\x07.Status\"\x0f\n\rGetCAsRequest\"7\n\x0bGetCAsReply\x12\x0f\n\x07\x63\x61Names\x18\x01 \x03(\t\x12\x17\n\x06status\x18\x02 \x01(\x0b\x32\x07.Status\"3\n\x15GetCertificateRequest\x12\x0e\n\x06\x63\x61Name\x18\x01 \x01(\t\x12\n\n\x02id\x18\x02 \x01(\x05\"<\n\x13GetCertificateReply\x12\x0c\n\x04\x63\x65rt\x18\x01 \x01(\t\x12\x17\n\x06status\x18\x02 \x01(\x0b\x32\x07.Status\"%\n\x13GetTemplatesRequest\x12\x0e\n\x06\x63\x61Name\x18\x01 \x01(\t\"C\n\x11GetTemplatesReply\x12\x15\n\rtemplateNames\x18\x01 \x03(\t\x12\x17\n\x06status\x18\x02 \x01(\x0b\x32\x07.Status\"b\n\x13GetCSRStatusRequest\x12\x0e\n\x06\x63\x61Name\x18\x01 \x01(\t\x12\x17\n\rcertRequestId\x18\x02 \x01(\x05H\x00\x12\x14\n\ncertSerial\x18\x03 \x01(\tH\x00\x42\x0c\n\nIDorSerial\"]\n\x11GetCSRStatusReply\x12\x13\n\x0b\x64isposition\x18\x01 \x01(\x05\x12\x1a\n\x12\x64ispositionMessage\x18\x02 \x01(\t\x12\x17\n\x06status\x18\x03 \x01(\x0b\x32\x07.Status\"\x7f\n\x18RevokeCertificateRequest\x12\x0e\n\x06\x63\x61Name\x18\x01 \x01(\t\x12\x14\n\x0cserialNumber\x18\x02 \x01(\t\x12!\n\x06reason\x18\x03 \x01(\x0e\x32\x11.RevokationReason\x12\x11\n\x04\x64\x61te\x18\x04 \x01(\x03H\x00\x88\x01\x01\x42\x07\n\x05_date\"1\n\x16RevokeCertificateReply\x12\x17\n\x06status\x18\x01 \x01(\x0b\x32\x07.Status\"E\n\x1dGetCertificateValidityRequest\x12\x0e\n\x06\x63\x61Name\x18\x01 \x01(\t\x12\x14\n\x0cserialNumber\x18\x02 \x01(\t\"^\n\x1bGetCertificateValidityReply\x12\x17\n\x06status\x18\x01 \x01(\x0b\x32\x07.Status\x12&\n\x08validity\x18\x02 \x01(\x0e\x32\x14.CertificateValidity*\xa5\x01\n\x10RevokationReason\x12\x0f\n\x0bUNSPECIFIED\x10\x00\x12\x12\n\x0eKEY_COMPROMISE\x10\x01\x12\x11\n\rCA_COMPROMISE\x10\x02\x12\x17\n\x13\x41\x46\x46ILIATION_CHANGED\x10\x03\x12\x0e\n\nSUPERSEDED\x10\x04\x12\x1a\n\x16\x43\x45SSATION_OF_OPERATION\x10\x05\x12\x14\n\x10\x43\x45RTIFICATE_HOLD\x10\x06*k\n\x13\x43\x65rtificateValidity\x12\x0e\n\nINCOMPLETE\x10\x00\x12\t\n\x05\x45RROR\x10\x01\x12\x0b\n\x07REVOKED\x10\x02\x12\t\n\x05VALID\x10\x03\x12\x0b\n\x07INVALID\x10\x04\x12\x14\n\x10UNDER_SUBMISSION\x10\x05\x32\x9e\x04\n\tCAService\x12/\n\tSubmitCSR\x12\x11.SubmitCSRRequest\x1a\x0f.SubmitCSRReply\x12&\n\x06GetCAs\x12\x0e.GetCAsRequest\x1a\x0c.GetCAsReply\x12>\n\x0eGetCertificate\x12\x16.GetCertificateRequest\x1a\x14.GetCertificateReply\x12\x38\n\x0cGetTemplates\x12\x14.GetTemplatesRequest\x1a\x12.GetTemplatesReply\x12\x38\n\x0cGetCSRStatus\x12\x14.GetCSRStatusRequest\x1a\x12.GetCSRStatusReply\x12/\n\tSetOption\x12\x11.SetOptionRequest\x1a\x0f.SetOptionReply\x12\x32\n\nGetOptions\x12\x12.GetOptionsRequest\x1a\x10.GetOptionsReply\x12G\n\x11RevokeCertificate\x12\x19.RevokeCertificateRequest\x1a\x17.RevokeCertificateReply\x12V\n\x16GetCertificateValidity\x12\x1e.GetCertificateValidityRequest\x1a\x1c.GetCertificateValidityReplyB\x07\xaa\x02\x04Grpcb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'caservice_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\252\002\004Grpc'
  _globals['_GETOPTIONSREPLY_OPTIONSENTRY']._options = None
  _globals['_GETOPTIONSREPLY_OPTIONSENTRY']._serialized_options = b'8\001'
  _globals['_REVOKATIONREASON']._serialized_start=1348
  _globals['_REVOKATIONREASON']._serialized_end=1513
  _globals['_CERTIFICATEVALIDITY']._serialized_start=1515
  _globals['_CERTIFICATEVALIDITY']._serialized_end=1622
  _globals['_STATUS']._serialized_start=19
  _globals['_STATUS']._serialized_end=58
  _globals['_SETOPTIONREQUEST']._serialized_start=60
  _globals['_SETOPTIONREQUEST']._serialized_end=119
  _globals['_SETOPTIONREPLY']._serialized_start=121
  _globals['_SETOPTIONREPLY']._serialized_end=162
  _globals['_GETOPTIONSREQUEST']._serialized_start=164
  _globals['_GETOPTIONSREQUEST']._serialized_end=183
  _globals['_GETOPTIONSREPLY']._serialized_start=186
  _globals['_GETOPTIONSREPLY']._serialized_end=324
  _globals['_GETOPTIONSREPLY_OPTIONSENTRY']._serialized_start=278
  _globals['_GETOPTIONSREPLY_OPTIONSENTRY']._serialized_end=324
  _globals['_SUBMITCSRREQUEST']._serialized_start=326
  _globals['_SUBMITCSRREQUEST']._serialized_end=395
  _globals['_SUBMITCSRREPLY']._serialized_start=397
  _globals['_SUBMITCSRREPLY']._serialized_end=506
  _globals['_GETCASREQUEST']._serialized_start=508
  _globals['_GETCASREQUEST']._serialized_end=523
  _globals['_GETCASREPLY']._serialized_start=525
  _globals['_GETCASREPLY']._serialized_end=580
  _globals['_GETCERTIFICATEREQUEST']._serialized_start=582
  _globals['_GETCERTIFICATEREQUEST']._serialized_end=633
  _globals['_GETCERTIFICATEREPLY']._serialized_start=635
  _globals['_GETCERTIFICATEREPLY']._serialized_end=695
  _globals['_GETTEMPLATESREQUEST']._serialized_start=697
  _globals['_GETTEMPLATESREQUEST']._serialized_end=734
  _globals['_GETTEMPLATESREPLY']._serialized_start=736
  _globals['_GETTEMPLATESREPLY']._serialized_end=803
  _globals['_GETCSRSTATUSREQUEST']._serialized_start=805
  _globals['_GETCSRSTATUSREQUEST']._serialized_end=903
  _globals['_GETCSRSTATUSREPLY']._serialized_start=905
  _globals['_GETCSRSTATUSREPLY']._serialized_end=998
  _globals['_REVOKECERTIFICATEREQUEST']._serialized_start=1000
  _globals['_REVOKECERTIFICATEREQUEST']._serialized_end=1127
  _globals['_REVOKECERTIFICATEREPLY']._serialized_start=1129
  _globals['_REVOKECERTIFICATEREPLY']._serialized_end=1178
  _globals['_GETCERTIFICATEVALIDITYREQUEST']._serialized_start=1180
  _globals['_GETCERTIFICATEVALIDITYREQUEST']._serialized_end=1249
  _globals['_GETCERTIFICATEVALIDITYREPLY']._serialized_start=1251
  _globals['_GETCERTIFICATEVALIDITYREPLY']._serialized_end=1345
  _globals['_CASERVICE']._serialized_start=1625
  _globals['_CASERVICE']._serialized_end=2167
# @@protoc_insertion_point(module_scope)
