#include<iostream>
#include<string>
#include<tuple>
#include <ctime>

using namespace std;

bool isPrime(const int64_t& n)
{
	for (size_t i = 2; i <= n / 2; ++i)
	{
		if (n % i == 0)
		{
			return false;
		}
	}
	return true;
}

pair<int64_t, int64_t> setPrimePair()
{
	pair<int64_t, int64_t> result;
	int64_t p = 2 + rand();
	int64_t q = 2 + rand();

	while (!isPrime(p) || !isPrime(q) || q == p)
	{
		p = 2 + rand();
		q = 2 + rand();
	}

	result.first = p;
	result.second = q;
	return result;
}

int64_t rev(int64_t e, int64_t ejler)
{
	if (e == 1)
	{
		return 1;
	}
	return (1 - rev(ejler%e, e) * ejler) / e + ejler;
}

int64_t cdn(int64_t c, int64_t d, int64_t n)      // work out c^d mod n
{
	int64_t value = 1;
	while (d > 0)
	{
		value *= c;
		value %= n;
		d--;
	}
	return value;
}

tuple<int64_t, int64_t, int64_t> cipherRSA()
{
	int64_t p = 0;
	int64_t q = 0;
	tie(p, q) = setPrimePair();
	int64_t n = p * q;
	int64_t ejler = (p - 1)*(q - 1);
	int64_t e = 2 + rand() % ejler;
	while (!isPrime(e))
	{
		e = 2 + rand() % ejler;
	}
	// count secret key e*d mod ejler = 1
	int64_t d = rev(e, ejler);

	//check is d correct;
	//int64_t c = (e*d) % ejler;

	return { e,d,n };
}

tuple<int64_t, int64_t> RSA_B_r(int64_t e, int64_t n)
{
	int64_t k = 1 + rand() % (n - 1);
	int64_t r = cdn(k, e, n);

	return{ k,r };
}

int64_t RSA_A_k(int64_t d, int64_t r, int64_t n)
{
	int64_t k = cdn(r,d,n);

	return k;
}

bool rsaAut(int64_t k1, int64_t k2)
{
	if (k1 == k2)
	{
		return true;
	}

	return false;
}

tuple<int64_t, int64_t, int64_t,int64_t,int64_t> clausShnorrScheme()
{
	int64_t p = 23;
	int64_t q = 11;
	while ((p - 1) % q != 0)
	{
		tie(p, q) = setPrimePair();
	}

	int64_t x = 8;
		//1 + rand() % (q - 1);

	int64_t g = 3;
	while (cdn(g, q, p) != 1);
	{
		//g = 1 + rand();
	}

	int64_t y = 4;
	while(static_cast<int64_t>(pow(g,x)*y)%p != 1)
	{
		y = 1 + rand();
	}

	return { p,q,g,x,y };
}

tuple<int64_t,int64_t> shnorr_A_r(int64_t g, int64_t p)
{
	int64_t k = 6;
		//1 + rand();
	int64_t r = cdn(g, k, p);

	return {k,r};
}

int64_t shnorr_B_e()
{
	int t = 52;
	int64_t e = 4;
		//1 + rand() % static_cast<int64_t>(pow(2,t)-1);

	return e;
}

int64_t shnorr_A_s(int64_t k, int64_t x, int64_t e,int64_t q)
{
	int64_t s = (k + x * e) % q;

	return s;
}

bool shnorrAut(int64_t r1, int64_t p, int64_t g, int64_t y, int64_t e, int64_t s)
{
	int64_t r2 = static_cast<int64_t>(pow(g, s)*pow(y, e)) % p;

	if (r1 == r2)
	{
		return true;
	}

	return false;
}

tuple<int64_t, int64_t, int64_t, int64_t> cipherFFS()
{
	int64_t p = 5;
	int64_t q = 7;
	//tie(p, q) = setPrimePair();
	int64_t n = p * q;

	int64_t v = 16;
		//1+rand();
	
	while (true)
	{
		bool isQuadrVich = false;

		for (int i = 1; i <= n; i++)
		{
			if (cdn(i, 2, n) == v)
			{
				isQuadrVich = true;
			}
		}

		if (isQuadrVich)
		{
			if (rev(v, n) > 0 && rev(v, n) < 9999999)
			{
				break;
			}
		}
		else
		{
			v = 1 + rand();
		}
	}

	int s = 1;
	while (true)
	{
		if (cdn(s, 2, n) == rev(v, n))
		{
			break;
		}
		s++;
	}

	return{ p,v,n,s };
}

tuple<int64_t,int64_t> FFS_A_z(int64_t n)
{
	int64_t r = 8;
		//1+rand()%n-1
	int64_t z = static_cast<int64_t>(pow(r, 2)) % n;

	return {r,z};
}

int64_t FFS_B_b(int64_t r, int64_t s, int64_t n, bool b)
{
	if (b)
	{
		return (r*s) % n;
	}
	
	return r;
}

bool FFSaut(bool b, int64_t z1, int64_t s, int64_t v, int64_t n,int64_t r)
{
	if (b)
	{
		int64_t z2 = static_cast<int64_t>((pow(((r*s) % n), 2)*v)) % n;
		if (z1 == z2)
		{
			return true;
		}
	}
	else
	{
		int64_t z2 = static_cast<int64_t>(pow(r, 2))%n;
		if (z1 == z2)
		{
			return true;
		}
	}

	return false;
}

void main()
{
	srand(time(0));

	/*//RSA autentifacation
	int64_t openKey, secretKey, n;
	tie(openKey, secretKey, n) = cipherRSA();

	int64_t k1, r;
	tie(k1, r) = RSA_B_r(openKey, n);
	int64_t k2 = RSA_A_k(secretKey, r, n);

	bool autent = rsaAut(k1, k2);*/
	
	/*//shnorr
	int64_t p, q, g, x, y;
	tie(p, q, g, x, y) = clausShnorrScheme();

	int64_t k, r;
	tie(k, r) = shnorr_A_r(g, p);
	int64_t e = shnorr_B_e();
	int64_t s = shnorr_A_s(k, x, e, q);
	bool aut = shnorrAut(r, p, g, y, e, s);*/

	int64_t p, v, n, s;
	tie(p,v,n,s) = cipherFFS();

	int64_t r, z;
	tie(r, z) = FFS_A_z(n);
	int64_t b = FFS_B_b(r,s,n,0);
	bool aut = FFSaut(0, z, s, v, n, r);
}