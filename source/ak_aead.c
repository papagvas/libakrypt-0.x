/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_aead.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_aead.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{64}}\f$.
    Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{64}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{64} + x^4 + x^3 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf64_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0, n = 0;
 ak_uint64 zv = 0, t = ((ak_uint64 *)y)[0], s = ((ak_uint64 *)x)[0];

 t = ((ak_uint64 *)y)[0];
 for( i = 0; i < 64; i++ ) {

   if( t&0x1 ) zv ^= s;
   t >>= 1;
   n = (s >> 63);
   s <<= 1;
   if( n ) s ^= 0x1B;
 }
 ((ak_uint64 *)z)[0] = zv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{128}}\f$.
    Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf128_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0, n = 0;
 ak_uint64 t, s0 = ((ak_uint64 *)x)[0], s1 = ((ak_uint64 *)x)[1];

 /* обнуляем результирующее значение */
 ((ak_uint64 *)z)[0] = 0; ((ak_uint64 *)z)[1] = 0;

 /* вычисляем  произведение для младшей половины */
 t = ((ak_uint64 *)y)[0];
 for( i = 0; i < 64; i++ ) {

   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   n = s1 >> 63;
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;
   if( n ) s0 ^= 0x87;
 }

 /* вычисляем  произведение для старшей половины */
 t = ((ak_uint64 *)y)[1];
 for( i = 0; i < 63; i++ ) {

   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   n = s1 >> 63;
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;
   if( n ) s0 ^= 0x87;
 }

 if( t&0x1 ) {
   ((ak_uint64 *)z)[0] ^= s0;
   ((ak_uint64 *)z)[1] ^= s1;
 }
}


/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{64}}\f$.
    Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{64}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{64} + x^4 + x^3 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf64_mul_pcmulqdq( ak_pointer z, ak_pointer x, ak_pointer y )
{
  const __m128i gm = _mm_set_epi64x( 0, 0x1B );
  __m128i xm = _mm_set_epi64x( 0, ((ak_uint64 *)x)[0] );
  __m128i ym = _mm_set_epi64x( 0, ((ak_uint64 *)y)[0] );

  __m128i cm = _mm_clmulepi64_si128( xm, ym, 0x00 );
  __m128i cx = _mm_set_epi64x( 0, cm[1] );

  xm = _mm_clmulepi64_si128( cx, gm, 0x00 ); xm[1] ^= cx[0];
  ym = _mm_set_epi64x( 0, xm[1] );
  xm = _mm_clmulepi64_si128( ym, gm, 0x00 );

 ((ak_uint64 *)z)[0] = cm[0]^xm[0];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{128}}\f$.
    Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf128_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b )
{
 __m128i am = *((__m128i *) a);
 __m128i bm = *((__m128i *) b);

 /* умножение */
 __m128i cm = _mm_clmulepi64_si128( am, bm, 0x00 ); // c = a0*b0
 __m128i dm = _mm_clmulepi64_si128( am, bm, 0x11 ); // d = a1*b1
 __m128i em = _mm_clmulepi64_si128( am, bm, 0x10 ); // e = a0*b1
 __m128i fm = _mm_clmulepi64_si128( am, bm, 0x01 ); // f = a1*b0

 /* приведение */
  ak_uint64 x3 = dm[1];
  ak_uint64 D = dm[0] ^ em[1] ^ fm[1] ^ (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57);

  cm[0] ^=  D ^ (D << 1) ^ (D << 2) ^ (D << 7);
  cm[1] ^=  em[0] ^ fm[0] ^ x3 ^ (x3 << 1) ^ (D >> 63) ^ (x3 << 2) ^ (D >> 62) ^ (x3 << 7) ^ (D >> 57);

  ((ak_uint64 *)z)[0] = cm[0];
  ((ak_uint64 *)z)[1] = cm[1];
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выполняет тестирование операции умножения в поле \f$ \mathbb F_{2^{64}}\f$. */
 static ak_bool ak_gf64_multiplication_test( void )
{
 int i = 0;
 char out[128];
 ak_uint64 values[8] =
  { 0x30017301ded13061LL, 0x6b1c06a3e91f0e11LL, 0x26a8f4fe69d51a14LL, 0x973a2f0c743fca03LL,
    0x895c56ed40853d3fLL, 0xae340229c65e5eceLL, 0xfe71dbde03a18ce2LL, 0x18e61c63bbbd5e52LL };

 /* сравнение с контрольными примерами */
 ak_uint64 y = 0xF000000000000011LL, x = 0x1aaabcda1115LL, z = 0, z1 = 0;
 (void)z1; /* неиспользуемая переменная */

 for( i = 0; i < 8; i++ ) {
    ak_gf64_mul_uint64( &z, &x, &y );
    if( z != values[i] ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "uint64 calculated %s on iteration %d", out, i );
      ak_ptr_to_hexstr_static( &values[i], 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "uint64 expected   %s on iteration %d", out, i );
      return ak_false;
    }
    x = y; y = z;
  }

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64

 /* сравнение с контрольными примерами */
 y = 0xF000000000000011LL, x = 0x1aaabcda1115LL, z = 0;
 for( i = 0; i < 8; i++ ) {
    ak_gf64_mul_pcmulqdq( &z, &x, &y );
    if( z != values[i] ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                           "pcmulqdq calculated %s on iteration %d", out, i );
      ak_ptr_to_hexstr_static( &values[i], 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                           "pcmulqdq expected   %s on iteration %d", out, i );
      return ak_false;
    }
    x = y; y = z;
  }

 /* проверка идентичности работы двух реализаций */
 y = 0xF1abcd5421110011LL, x = 0x1aaabcda1115LL, z = 0;
 for( i = 0; i < 1000; i++ ) {
    ak_gf64_mul_uint64( &z, &x, &y );
    ak_gf64_mul_pcmulqdq( &z1, &x, &y );
    if( z != z1 ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated   %s", out );
      ak_ptr_to_hexstr_static( &z1, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
      return ak_false;
    }
    x = y; y = z;
  }
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выполняет тестирование операции умножения в поле \f$ \mathbb F_{2^{128}}\f$. */
 static ak_bool ak_gf128_multiplication_test( void )
{
 int i = 0;
 char out[128];

 ak_uint8 a8[16] = { 0x5d, 0x47, 0x53, 0x5d, 0x72, 0x6f, 0x74, 0x63, 0x65, 0x56, 0x74, 0x73, 0x65, 0x54, 0x5b, 0x7b };
 ak_uint8 b8[16] = { 0x5d, 0x6e, 0x6f, 0x72, 0x65, 0x75, 0x47, 0x5b, 0x29, 0x79, 0x61, 0x68, 0x53, 0x28, 0x69, 0x48 };
 ak_uint8 result[16], result2[16];

 ak_uint128 a, b, m;
  a.q[0] = 0x63746f725d53475dLL; a.q[1] = 0x7b5b546573745665LL;
  b.q[0] = 0x5b477565726f6e5dLL; b.q[1] = 0x4869285368617929LL;
  m.q[0] = 0x7e4e10da323506d2LL; m.q[1] = 0x040229a09a5ed12eLL;
  memset( result, 0, 16 );
  memset( result2, 0, 16 );
 (void)i; /* неиспользуемая переменная */

 // сравниваем данные
 if( !ak_ptr_is_equal( a8, a.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant in memory representation");
   return ak_false;
 }
 if( !ak_ptr_is_equal( b8, b.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant in memory representation");
   return ak_false;
 }

 // проверяем пример из white paper для GCM (применение pcmulqdq для GCM)
 // a = 0x7b5b54657374566563746f725d53475d
 // b = 0x48692853686179295b477565726f6e5d
 // GFMUL128 (a, b) = 0x40229a09a5ed12e7e4e10da323506d2

 ak_gf128_mul_uint64( result, &a, &b );
 if( !ak_ptr_is_equal( result, m.q, 16 )) {
   ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated %s", out );
   ak_ptr_to_hexstr_static( m.q, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 expected   %s", out );
   return ak_false;
 }

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64

 ak_gf128_mul_pcmulqdq( result2, &a, &b );
 /* сравнение с константой */
 if( !ak_ptr_is_equal( result2, m.q, 16 )) {
   ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
   ak_ptr_to_hexstr_static( m.q, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq expected   %s", out );
   return ak_false;
 }
 /* сравнение с другим способом вычисления */
 if( !ak_ptr_is_equal( result2, result, 16 )) {
   ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
   ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated   %s", out );
   return ak_false;
 }

 /* сравнение для двух способов на нескольких значениях */
 for( i = 1; i < 1000; i++ ) {
   a.q[0] = b.q[1]; a.q[1] = b.q[0];
   memcpy( b.b, result, 16 );

   ak_gf128_mul_uint64( result, &a, &b );
   ak_gf128_mul_pcmulqdq( result2, &a, &b );
   if( !ak_ptr_is_equal( result, result2, 16 )) {
     ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
     ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                          "pcmulqdq calculated %s on iteration %d", out, i );
     ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
     ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                          "uint64 calculated   %s on iteration %d", out, i );
     return ak_false;
   }
 }
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_gfn_multiplication_test( void )
{
 int audit =  audit = ak_log_get_level();

 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing the Galois fileds arithmetic started");

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ ,
                                       "using pcmulqdq for multiplication in finite Galois fields");
#endif

 if( ak_gf64_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^64)");
   return ak_false;
 } else ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^64) is OK");

 if( ak_gf128_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^128)");
   return ak_false;
 } else ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^128) is OK");

 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ ,
                                         "testing the Galois fileds arithmetic ended successfully");
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_aead.c  */
/* ----------------------------------------------------------------------------------------------- */