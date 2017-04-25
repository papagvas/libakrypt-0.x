/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
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
/*   ak_buffer.h                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_BUFFER_H__
#define    __AK_BUFFER_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения двоичных данных

  Класс рассматривается как хранилище данных, для которых контролируется размер и функции
  выделения/освобождения памяти. Класс может использоваться для хранения строк.                    */
/* ----------------------------------------------------------------------------------------------- */
 struct buffer {
   /*! \brief размер данных (в байтах) */
   size_t size;
   /*! \brief указатель на данные */
   ak_pointer data;
   /*! \brief флаг выделения памяти/владения данными */
   ak_bool flag;
   /*! \brief указатель на функцию выделения памяти под данные */
   ak_function_alloc *alloc;
   /*! \brief указатель на функцию освобождения данных */
   ak_function_free *free;
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация буффера */
 int ak_buffer_create( ak_buffer );
/*! \brief Инициализация буффера и выделение памяти фиксированной длины */
 int ak_buffer_create_size( ak_buffer , const size_t );
/*! \brief Инициализация буффера с заданными обработчиками выделения и освобождения памяти */
 int ak_buffer_create_function_size( ak_buffer ,
                                          ak_function_alloc *, ak_function_free *, const size_t );
/*! \brief Функция освобождает память, выделенную под данные (поле data структуры struct buffer ) */
 int ak_buffer_free( ak_buffer );
/*! \brief Функция выделяет память под данные, хранимые в буффере */
 int ak_buffer_alloc( ak_buffer , const size_t );
/*! \brief Уничтожение данных, хранящиеся в полях структуры struct buffer */
 int ak_buffer_destroy( ak_buffer );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_buffer.h  */
/* ----------------------------------------------------------------------------------------------- */
