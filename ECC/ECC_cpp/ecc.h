#ifndef MYHEADER_H
#define MYHEADER_H

#include<math.h>
#include<random>
#include<iostream>
#include<vector>
using namespace std;
long long mem = 0;
// point is a struct type with x and y coordinates of a point.
struct point{
    long long x, y;
};

// cryptedMessage is a struct type with C1 and C2 as points.
struct cryptedMessage{
    point * C1;
    point * C2;
};

// message is a struct type with x and y coordinates of a message.
struct message{
    long long x, y;
};

class ecc {
private:
    long long p, a, b; // curve parameters
    long long privateKey; // private key of ECC
    
    // methods for generic functions
    long long extended_euclidean(long long x, long long y, long long s1, long long s2);
    long long mod(long long x);
    long long get_random();
    long long power(long long base, long long exp);

    // methods for points arithmetics
    point * create_point(long long x, long long y);
    bool is_points_same(point *p1, point *p2);
    long long get_slope(point *p1, point *p2);
    bool is_identity_point(point *p);
    point* add_points(point *p1, point *p2);
    point* sub_points(point *p1, point *p2);
    point * multiply_point(long long x, point * p);

    // methods for ECC operations
    bool is_quadradic_non_residue(long long y);
    void set_generator();
    void generate_keys();

    // method for decryption
    message* decrypt(cryptedMessage *C);
public:
    point * publicKey; //Public key
    point * generator; //Generator
    
    bool is_suitable_prime(long long p);
    // constructor 
    ecc(long long p, long long a, long long b);

    // methods for encryption
    message* create_message(long long x, long long y);
    cryptedMessage* encrypt(message *M);

    // backdoor function for decryption
    message* decrypt_backdoor(cryptedMessage *C);
};

// is_suitable_prime check is a number is of format 4n+3 and is prime.
bool ecc::is_suitable_prime(long long p){
    if (p % 4 != 3) return false;
    if (p < 2) return false;
    long pSqrt = sqrt(p);
    for (long long i = 2; i <= pSqrt; i++)
        if (p % i == 0)
            return false;
    return true;
}


// Constructor that creates elliptic curve y^2 = x^3 + ax + b with given parameters
ecc::ecc(long long p, long long a, long long b)
{   
    if( !is_suitable_prime(p) ){
        cout<<"Error: p must be a prime number greater than 2 of format 4n + 3.\n";
        exit(1);
    }
    ecc::p = p;
    ecc::a = a;
    ecc::b = b;
    ecc::set_generator();
    ecc::generate_keys();
}

// extended_euclidean will return the inverse of the a w.r.t p.
long long ecc::extended_euclidean(long long a, long long b, long long s1, long long s2){
    if (b == 1){
        return mod(s2);
    }
    if ( b > a ){
        long long t = b; b = a; a = t;
    }
    if(b == 0 ){
        cout<<"Error: unexpected error\n";
        exit(1);
    }
    long long q = mod(a/b);
    long long r = mod(a%b);
    return extended_euclidean(b, r, s2, s1 - q*s2);
}

// mod performs modulus operation.
long long ecc::mod(long long x){
    if( x >= 0)  return x%ecc::p;
    long q = ((-x) / ecc::p)+1;
    return (x + q * ecc::p ) % ecc::p;
}

// get_random generates a random number
long long ecc::get_random(){
    random_device  rd;
    uniform_int_distribution<long long> dist(2, ecc::p-1);
    long long r1 = dist(rd), r2 = dist(rd);
    return mod(r1 * r2);
}

//pow raisea a base to a exponent and perform modulo operation with p
long long ecc::power(long long base, long long exp) {
    if ( exp == 0 ) return 1;
    exp = exp % (ecc::p - 1); // fermet's little theorem a^(p-1) mod p = 1 mod p
    string exp_bin = "";  // represented in reverse order
    while (exp > 0){
        char c = exp%2 == 1 ? '1' : '0';
        exp_bin += c;
        exp >>= 1;
    }
    long len = exp_bin.size();
    vector<long long>binary_powers(len);
    binary_powers[0] = mod(base);
    long long res = exp_bin[0] == '1'? base: 1;
    for( long i = 1; i < len; i++){
        binary_powers[i] = mod(binary_powers[i-1] * binary_powers[i-1]);
        if(exp_bin[i] == '1'){
            res = mod(res * binary_powers[i]);
        }
    }
    return res;
}

// create_points creates a point dynamically and return a pointer to it.
point * ecc::create_point(long long x, long long y){
    mem++;

    return new point({x,y});
}

// is_points_same checks if two points are same.
bool ecc::is_points_same(point *p1, point *p2){
    if (p1->x == p2->x && p1->y == p2->y){
        return true;
    } 
    return false;
}

// get_slope returns the slope.
long long ecc::get_slope(point *p1, point *p2){
    if( ecc::is_points_same(p1, p2) ){
        long long num = mod((3*p1->x*p1->x) + ecc::a), denom = mod(p1->y+p1->y);
        return (num * extended_euclidean(ecc::p, denom, 0, 1)) % ecc::p ;
    }
    long long num = (mod(p2->y - p1->y)), denom = extended_euclidean(ecc::p, mod(p2->x - p1->x), 0, 1);
    return mod(num * denom );
}

// is_identity_point will check if the point is identity
bool ecc::is_identity_point(point * p1){
    if ( p1->x == -1 && p1->y == -1)    return true;
    return false;
}

// add_points adds two points in the curve.
point * ecc::add_points(point *p1, point *p2){
    if( is_identity_point(p1) ) return p2; 
    else if (is_identity_point(p2) ) return p1;
    else if( p1->x == p2->x && p1->y == mod(-p2->y)){
        return ecc::create_point(-1,-1);
    } 
    long long slope = ecc::get_slope(p1, p2);
    long long x = mod(slope*slope - p1->x - p2->x);
    long long y = mod( -(p1->y + slope*(x - p1->x)));

    return ecc::create_point(x, y);
}

// sub_points subtracts two points in the curve.
point * ecc::sub_points(point *p1, point *p2){
    if (is_identity_point(p2) ) return p1;
    point *t = ecc::create_point(p2->x, mod(-(p2->y)));
    point * res = add_points(p1, t);
    mem--;

    delete t;
    return res;
}

// multiply_point multiplies a point with an integer value
point *ecc::multiply_point( long long x, point *p1){
    point *t; // temporary point
    if( x <= 0 ){
        cout<<"Error: cannot multiply point with a negative integer or zero\n";
        exit(1);
    } 
    else if (x == 1 || is_identity_point(p1)){
        return p1;
    }
    t = ecc::add_points(p1, p1);
    for(  long long i=3; i<=x; i++){
        point* del = t;
        t = ecc::add_points(t, p1);
        delete del;
    }
    return t;
}

// is_quadradic_non_residue finds wether a given value as qudardic solution
bool ecc::is_quadradic_non_residue(long long y){
    long long exponent = (ecc::p - 1) / 2;
    if (mod(ecc::power(y, exponent)) == 1) return true;
    return false;
}

// get_generator creates all the points in the curve with integer values and gives a random point as a generator. Under the assumption that all the points are in the cyclic sub group.
void ecc::set_generator(){
    vector<point*> cyclic_sub_group;
    long long exponent = (ecc::p + 1) / 4;
    for( long long x = 1; x < ecc::p; x++){
        long long y2 = x*x*x + a*x + b; // y2 = x3 + ax + b - elliptic curve
        if (is_quadradic_non_residue(y2)) {
            point *p1 = ecc::create_point(mod(x), power(y2, exponent));
            point *p2 = ecc::create_point(p1->x, mod(-(p1->y)));
            cyclic_sub_group.push_back(p1);
            cyclic_sub_group.push_back(p2);
        }
    }
    long long len = cyclic_sub_group.size();
    if (len == 0) {
        cout << "Warning: no point in the cyclic subgroup." << endl;
        exit(0);
    }
    
    long long randInd = (get_random() * get_random() ) % len;
    ecc::generator = cyclic_sub_group[randInd];
    for ( long long i = 0; i < len; i++) {
        if( i != randInd ) {
            delete cyclic_sub_group[i];
        }
    }
    cout<<"Generator: ("<<generator->x << ", "<<generator->y<<")\n";
    return;
}

// generate_keys generates private and public keys.
void ecc::generate_keys(){
    ecc::privateKey = get_random();
    ecc::publicKey = multiply_point(ecc::privateKey, ecc::generator);
    cout<<"Private Key: "<<privateKey<<endl;
    cout<<"Public Key: ("<<ecc::publicKey->x<<", "<<ecc::publicKey->y<<")\n";
    return;
}

// create_message creates a message dynamically and return a pointer to it.
message * ecc::create_message(long long x, long long y) {

    return new message({x,y});
}

// encrypt encrypts a message using public key.
cryptedMessage* ecc::encrypt(message *m){
    cryptedMessage *C = new cryptedMessage;

    long long k = get_random();
    cout<<"K : "<<k<<endl;
    C->C1 = ecc::multiply_point(k, ecc::generator); 
    point * M = ecc::create_point(m->x, m->y);
    point * t = multiply_point(k, ecc::publicKey);
    C->C2 = add_points(M, t);
    delete M;
    return C;
}

// decrypt decrypts a message using private key.
message* ecc::decrypt(cryptedMessage *C){
    point * M = sub_points(C->C2, multiply_point(ecc::privateKey, C->C1));

    message *m = new message;
    m->x = M->x; m->y = M->y;
    return m;
}

// decrypt_backdoor decrypts a message using private key, but with a backdoor.
message* ecc::decrypt_backdoor(cryptedMessage * C){
    return decrypt(C);
}

#endif