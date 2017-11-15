#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "x13.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "Lyra2RE.h"
    #include "Lyra2.h"
    #include "Lyra2REV2.h"
    #include "Lyra2Z.h"
    #include "sia.h"
    #include "cryptonight.h"
    #include "decred.h"
    #include "lbry.h"
    #include "pascal.h"
    #include "hsr.h"
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowTypeError(x)
#define NanScope()

using namespace node;
using namespace v8;

NAN_METHOD(quark) {
	NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x11) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(hsr) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    hsr_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(scrypt) {
	NanScope();

	if (info.Length() < 3)
		return THROW_ERROR_EXCEPTION("You must provide buffer to hash, N value, and R value");

	Local<Object> target = info[0]->ToObject();

	if(!Buffer::HasInstance(target))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	Local<Number> numn = info[1]->ToNumber();
	unsigned int nValue = numn->Value();
	Local<Number> numr = info[2]->ToNumber();
	unsigned int rValue = numr->Value();

	char * input = Buffer::Data(target);
	char output[32];

	uint32_t input_len = Buffer::Length(target);

	scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}



NAN_METHOD(scryptn) {
	NanScope();

	if (info.Length() < 2)
		return THROW_ERROR_EXCEPTION("You must provide buffer to hash and N factor.");

	Local<Object> target = info[0]->ToObject();

	if(!Buffer::HasInstance(target))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	Local<Number> num = info[1]->ToNumber();
	unsigned int nFactor = num->Value();

	char * input = Buffer::Data(target);
	char output[32];

	uint32_t input_len = Buffer::Length(target);

	//unsigned int N = 1 << (getNfactor(input) + 1);
	unsigned int N = 1 << nFactor;

	scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(scryptjane) {
    NanScope();

    if (info.Length() < 5)
        return THROW_ERROR_EXCEPTION("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("First should be a buffer object.");

    Local<Number> num = info[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = info[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = info[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = info[4]->ToNumber();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(keccak) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(bcrypt) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(skein) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    skein_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(groestl) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(groestlmyriad) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(blake) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(fugue) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(qubit) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(hefty1) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(shavite3) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x13) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(nist5) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(sha1) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x15) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(fresh) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(lyra2re) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2re_hash(input, output);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(lyra2rev2) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2rev2_hash(input, output, 8192);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(lyra2z) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2z_hash(input, output);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(sia) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);
    char output[32];

    sia_hash(input, output, input_len);

	info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(cryptonight) {
    NanScope();

    bool fast = false;

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    if (info.Length() >= 2) {
        if(!info[1]->IsBoolean())
            return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
        fast = info[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(decred) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);
    char output[32];

    decred_hash(input, output);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(lbry) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);
    char output[32];

    lbry_hash(input, output);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(pascal) {
    NanScope();

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);
    char output[32];

    pascal_hash(input, output);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

void init(Handle<Object> exports) {
    exports->Set(Nan::New("quark").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(quark)->GetFunction());
    exports->Set(Nan::New("x11").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(x11)->GetFunction());
    exports->Set(Nan::New("hsr").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(hsr)->GetFunction());
    exports->Set(Nan::New("scrypt").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(scrypt)->GetFunction());
    exports->Set(Nan::New("scryptn").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(scryptn)->GetFunction());
    exports->Set(Nan::New("scryptjane").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(scryptjane)->GetFunction());
    exports->Set(Nan::New("keccak").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(keccak)->GetFunction());
    exports->Set(Nan::New("bcrypt").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(bcrypt)->GetFunction());
    exports->Set(Nan::New("skein").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(skein)->GetFunction());
    exports->Set(Nan::New("groestl").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(groestl)->GetFunction());
    exports->Set(Nan::New("groestlmyriad").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(groestlmyriad)->GetFunction());
    exports->Set(Nan::New("blake").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(blake)->GetFunction());
    exports->Set(Nan::New("fugue").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(fugue)->GetFunction());
    exports->Set(Nan::New("qubit").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(qubit)->GetFunction());
    exports->Set(Nan::New("hefty1").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(hefty1)->GetFunction());
    exports->Set(Nan::New("shavite3").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(shavite3)->GetFunction());
    exports->Set(Nan::New("x13").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(x13)->GetFunction());
    exports->Set(Nan::New("nist5").ToLocalChecked(),Nan::New<v8::FunctionTemplate>(nist5)->GetFunction());
    exports->Set(Nan::New("sha1").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(sha1)->GetFunction());
    exports->Set(Nan::New("x15").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(x15)->GetFunction());
    exports->Set(Nan::New("fresh").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(fresh)->GetFunction());
    exports->Set(Nan::New("lyra2re").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(lyra2re)->GetFunction());
    exports->Set(Nan::New("lyra2rev2").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(lyra2rev2)->GetFunction());
    exports->Set(Nan::New("lyra2z").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(lyra2z)->GetFunction());
    exports->Set(Nan::New("sia").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(sia)->GetFunction());
    exports->Set(Nan::New("decred").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(decred)->GetFunction());
    exports->Set(Nan::New("lbry").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(lbry)->GetFunction());
    exports->Set(Nan::New("pascal").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(pascal)->GetFunction());
    exports->Set(Nan::New("cryptonight").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(cryptonight)->GetFunction());
}

NODE_MODULE(multihashing, init)
