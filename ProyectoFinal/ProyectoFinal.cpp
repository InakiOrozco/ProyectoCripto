#include <stdio.h>
#include <sodium.h>
#include <iostream>
#include <string>

#include <algorithm>

#define DEBUG 1

using namespace std;

constexpr auto CHUNK_SIZE = 4096;

using std::cout; using std::cerr;
using std::endl; using std::string;
string readFileIntoString(const string& path) {
    struct stat sb {};
    string res;

    FILE* input_file = fopen(path.c_str(), "r");
    if (input_file == nullptr) {
        perror("fopen");
    }

    stat(path.c_str(), &sb);
    res.resize(sb.st_size);
    fread(const_cast<char*>(res.data()), sb.st_size, 1, input_file);
    fclose(input_file);

    return res;
}

static int
encriptar(const char* archivo_resultante, const char* archivo_original,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    //lo abre con rb para poder leer archivos en general.
    fp_s = fopen(archivo_original, "rb");

    //lo abre con wb para poder escribir en el archivo.
    fp_t = fopen(archivo_resultante, "wb");

    //Esta línea inicializa la encripción basándose en una llave secreta y un header, la llave no se volverá a usar.
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);

    fwrite(header, 1, sizeof header, fp_t);

    //Mientras el archivo original no haya terminado se va a ejecutar este código que encripta cada caracter y lo guarda en el archivo resultante (fp_t)
    do {
        //largo del archivo original
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        //Encripta el mensaje con el estado &st que se inicializó arriba, de largo rlen y el tag FINAL
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
            NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    //Cierra los dos archivos al terminar la encripción y regresa 0
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int
desencriptar(const char* archivo_resultante, const char* archivo_original,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    //Abre el archivo original a desencriptar y crea un archivo resultante donde estará el resultado.
    fp_s = fopen(archivo_original, "rb");
    fp_t = fopen(archivo_resultante, "wb");
    fread(header, 1, sizeof header, fp_s);

    //Si el pull inicial del state no es 0 por falta de header o incompleto, va a ret que cierra los dos archivos. 
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret;
    }
    //Mientras no termine el documento de desencripción no termina el while.
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);

        //Si no regresa 0 la desencripción (está corrupto el archivo) va a ret.
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
            buf_in, rlen, NULL, 0) != 0) {
            goto ret;
        }

        //Si termina el archivo antes de que se espere salta a ret.
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret;
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

static int
firmar(const char* archivo_resultante, const char* archivo_original,
    const unsigned char publicKey[crypto_sign_PUBLICKEYBYTES], const unsigned char privateKey[crypto_sign_SECRETKEYBYTES])
{
    string file_contents;
    file_contents = readFileIntoString(archivo_original);
    const int file_length = file_contents.length();

    //reservamos la memoria del mensaje firmado
    unsigned char* signed_message = new unsigned char[crypto_sign_BYTES + file_length];
    unsigned long long signed_message_len;

    //convertimos a unsigned char* el string
    unsigned char* mensaje = new unsigned char[file_length+1];
    
    std::copy(file_contents.begin(), file_contents.end(), mensaje);
    mensaje[file_contents.length()] = 0;

    if (DEBUG) {
        cout << "file_contents: " << file_contents << endl;
        cout << endl;
        cout << "crypto_sign_BYTES: " << crypto_sign_BYTES << endl;
        cout << endl;
        cout << "file_length: " << file_length << endl;
        cout << endl;
        cout << "crypto_sign_BYTES + file_length: " << crypto_sign_BYTES + file_length<< endl;
        cout << endl;
        cout << "mensaje: " << mensaje << endl;
        cout << endl;
        cout << "public_key: " << publicKey << endl;
        cout << endl;
        cout << "&signed_message_len" << &signed_message_len << endl;
        cout << endl;
        cout << "signed_message before: " << signed_message << endl;
        cout << endl;
    }

    crypto_sign(signed_message, &signed_message_len, mensaje, file_length, privateKey);

    if (DEBUG) {
        cout << "signed_message after: " << signed_message << endl;
        cout << endl;
    }

    unsigned char* unsigned_message = new unsigned char[file_length];
    unsigned long long unsigned_message_len;

    if (crypto_sign_open(unsigned_message, &unsigned_message_len,
        signed_message, signed_message_len, publicKey) != 0) {
        //SE FIRMO MAL
        return 1;
    }

    const char* result = (const char*)signed_message;

    if (!DEBUG) {
        FILE* signedFile;
        signedFile = fopen(archivo_resultante, "w");
        if (signedFile != NULL)
        {
            fputs(result, signedFile);
            fclose(signedFile);
        }
        else {
            return 1;
        }
    }

    //borramos las variables que reservamos
    delete[] mensaje;
    delete[] signed_message;
    delete[] unsigned_message;

    return 0;
}

static int
verificar(const char* archivo, const unsigned char publicKey[crypto_sign_PUBLICKEYBYTES])
{
    string file_contents;
    file_contents = readFileIntoString(archivo);
    unsigned long long file_length = file_contents.length();

    //si está mal creado el archivo firmado ni tiene caso que se haga nada más
    if (file_length < crypto_sign_BYTES) {
        return 1;
    }

    string signature = file_contents.substr(0, crypto_sign_BYTES);
    file_contents = file_contents.substr(crypto_sign_BYTES);

    //ahora que separamos el mensaje del archivo reajustamos el largo
    file_length = file_contents.length();
    
    //convertimos a unsigned char* el string
    unsigned char* mensaje = new unsigned char[file_length + 1];

    std::copy(file_contents.begin(), file_contents.end(), mensaje);
    mensaje[file_contents.length()] = 0;

    //reservamos la memoria de la firma y la convertimos a char*
    unsigned char* sig = new unsigned char[crypto_sign_BYTES + 1];

    std::copy(signature.begin(), signature.end(), sig);
    sig[signature.length()] = 0;

    cout << sig << endl;
    cout << endl;
    cout << mensaje << endl;
    cout << endl;
    cout << crypto_sign_BYTES;
    cout << endl;
    cout << file_length << endl;
    cout << endl;
    cout << file_length + crypto_sign_BYTES;
    cout << endl;
    cout << publicKey << endl;

    if (crypto_sign_verify_detached(sig, mensaje, file_length, publicKey) != 0) {
        cout << "La firma no es válida";
        return 1;
    }
    cout << "La firma es válida";

    //borramos las variables que reservamos
    delete[] mensaje;
    delete[] sig;

    return 0;
}

static int
escribirSK(const char* archivo, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    FILE* keyFile;
    keyFile = fopen(archivo, "w");
    if (keyFile != NULL)
    {
        fputs(reinterpret_cast<const char*>(key), keyFile);
        fclose(keyFile);
    }
    else {
        return 1;
    }
    return 0;
}

static int
escribirKeys(const char* archivo_public, const char* archivo_private, const unsigned char publicKey[crypto_sign_PUBLICKEYBYTES], const unsigned char privateKey[crypto_sign_SECRETKEYBYTES])
{
    FILE* publicKeyFile;
    publicKeyFile = fopen(archivo_public, "w");
    if (publicKeyFile != NULL)
    {
        fputs(reinterpret_cast<const char*>(publicKey), publicKeyFile);
        fclose(publicKeyFile);
    }
    else {
        return 1;
    }

    FILE* privateKeyFile;
    privateKeyFile = fopen(archivo_private, "w");
    if (privateKeyFile != NULL)
    {
        fputs(reinterpret_cast<const char*>(privateKey), privateKeyFile);
        fclose(privateKeyFile);
    }
    else {
        return 1;
    }
    return 0;
}

int
extraerSK(const char* archivo, unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]){
    string file_contents;
    file_contents = readFileIntoString(archivo);
    const int file_length = file_contents.length();

    std::copy(file_contents.begin(), file_contents.end(), key);
    key[file_contents.length()] = 0;

    return 0;
}

int
extraerPublicKey(const char* archivo, unsigned char publicKey[crypto_sign_PUBLICKEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(archivo);
    const int file_length = file_contents.length();

    std::copy(file_contents.begin(), file_contents.end(), publicKey);
    publicKey[file_contents.length()] = 0;

    return 0;
}

int
extraerPrivateKey(const char* archivo, unsigned char privateKey[crypto_sign_SECRETKEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(archivo);
    const int file_length = file_contents.length();

    //convertimos a unsigned char* el string
    unsigned char* llave = new unsigned char[file_length + 1];

    std::copy(file_contents.begin(), file_contents.end(), privateKey);
    privateKey[file_contents.length()] = 0;

    return 0;
}

void showChoices()
{
    cout << "MENU" << endl;
    cout << "1: Generación de claves " << endl;
    cout << "2: Recuperación de claves" << endl;
    cout << "3: Cifrado de archivos " << endl;
    cout << "4: Descifrado de archivos " << endl;
    cout << "5: Firma de archivos " << endl;
    cout << "6: Verificación de firma de archivos" << endl;
    cout << "0: Salir" << endl;
    cout << "Ingresa tu elección :";
}

int
main(void)
{
    //Si no se puede inicializar la librería de libsodium regresa error
    if (sodium_init() != 0) {
        return 1;
    }

    //Se declara la llave secreta para cifrar/descifrar
    unsigned char secretKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    crypto_secretstream_xchacha20poly1305_keygen(secretKey);

    //Se declara la llave pública
    unsigned char publicKey[crypto_sign_PUBLICKEYBYTES];

    //Se declara la llave privada 
    unsigned char privateKey[crypto_sign_SECRETKEYBYTES];
    
    //Se guarda el par de llaves
    crypto_sign_keypair(publicKey, privateKey);

    string a, b, c;
    char origin[300], destiny[300];
    int choice, eleccion;
    do
    {
        showChoices();
        cin >> choice;
        switch (choice)
        {
        case 0:
            break;
        case 1:
            do {
                cout << "1: Obtener una llave secreta " << endl;
                cout << "2: Obtener una llave pública y privada " << endl;
                cout << "0: Salir " << endl;
                cout << "Ingresa tu elección :";
                cin >> eleccion;
                switch (eleccion) {
                case 0:
                    break;
                case 1:
                    cout << "Escriba la dirección donde se guardará la llave: ";
                    cin >> a;
                    strcpy(origin, a.c_str());
                    if (escribirSK(origin, secretKey) != 0) {
                        return 1;
                    }
                    break;
                case 2:
                    cout << "Escriba la dirección donde se guardará la llave pública: ";
                    cin >> a;
                    cout << "Escriba la dirección donde se guardará la llave privada: ";
                    cin >> b;
                    strcpy(origin, a.c_str());
                    strcpy(destiny, b.c_str());
                    if (escribirKeys(origin, destiny, publicKey, privateKey) != 0) {
                        return 1;
                    }
                    break;
                default:
                    cout << "Invalid input" << endl;
                }
            } while (eleccion != 0);
            break;
        case 2:
            do {
                cout << "1: Extraer una llave secreta " << endl;
                cout << "2: Extraer una llave pública y privada " << endl;
                cout << "0: Salir " << endl;
                cout << "Ingresa tu elección :";
                cin >> eleccion;
                switch (eleccion) {
                case 0:
                    break;
                case 1:
                    cout << "Escriba la dirección donde se guardará la llave: ";
                    cin >> a;
                    strcpy(origin, a.c_str());
                    if (extraerSK(origin, secretKey) != 0) {
                        return 1;
                    }
                    break;
                case 2:
                    cout << "Escriba la dirección donde se guardará la llave pública: ";
                    cin >> a;
                    cout << "Escriba la dirección donde se guardará la llave privada: ";
                    cin >> b;
                    strcpy(origin, a.c_str());
                    strcpy(destiny, b.c_str());
                    if (extraerPublicKey(origin, publicKey) != 0) {
                        return 1;
                    }
                    if (extraerPrivateKey(destiny, privateKey) != 0) {
                        return 1;
                    }
                    break;
                default:
                    cout << "Invalid input" << endl;
                }
            } while (eleccion != 0);
            break;
        case 3:
            cout << "Escriba la dirección del archivo a encriptar: ";
            cin >> a;
            cout << "Escriba la dirección del archivo resultante: ";
            cin >> b;
            strcpy(origin, a.c_str());
            strcpy(destiny, b.c_str());

            if (encriptar(destiny, origin, secretKey) != 0) {
                return 1;
            }
            break;
        case 4:
            cout << "Escriba la dirección del archivo encriptado: ";
            cin >> a;
            cout << "Escriba la dirección del archivo desencriptado: ";
            cin >> b;
            strcpy(origin, a.c_str());
            strcpy(destiny, b.c_str());
            if (desencriptar(destiny, origin, secretKey) != 0) {
                return 1;
            }
            break;
        case 5:
            cout << "Escriba la dirección del archivo a firmar: ";
            cin >> a;
            cout << "Esciba la dirección del archivo firmado: ";
            cin >> b;
            strcpy(origin, a.c_str());
            strcpy(destiny, b.c_str());
            if (firmar(destiny, origin, publicKey, privateKey) != 0) {
                return 1;
            }
            break;
        case 6:
            cout << "Escriba la dirección del archivo a verificar: ";
            cin >> a;
            strcpy(origin, a.c_str());
            if (verificar(origin, publicKey) != 0){
                return 1;
            }
            break;
        default:
            cout << "Invalid input" << endl;
        }
    } while (choice != 0);

    //Si todo funcionó, regresa código de éxito.
    return 0;
}