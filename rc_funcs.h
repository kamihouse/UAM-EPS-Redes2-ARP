/***************************************************************************
 * Include : rc_funcs                 Versión : 4.0.0     FECHA : 08/feb/07
 *
 * Descripcion :
 *   Funciones auxiliares para practicas de Redes de Comunicaciones
 *
 * Fecha : 14/jul/00
 * Autor : Sergio Lopez y Antonio Martinez
 * Centro: UAM - EPS
 *
 * Cambios:
 *   * 05/dic/00. V2.0.1. Antonio Martinez
 *      - Cambiado tipo de datos del mensaje en calcula_crc a BYTE * para
 *        consistencia con tipos de level1.
 *   * 20/sep/02: V3.0.0. Antonio Martinez
 *      - Adaptado a los nuevos nombres de funciones de la interfaz nivel1
 *   * 08/feb/07: V4.0.0 Manuel Freire
 *      - Eliminada 'ObtenerDirDestino'
 *      - Incorporada lee_cadena_ip (hace casi lo mismo) y lee_cadena_eth
 *      - Eliminados acentos
 *      - Modificado prototipo de calcula_crc para simplificar su uso
 *   * 07/mar/07: V4.0.1 Jose Hernandez & Manuel Freire
 *      - Incorporado calcula_checksum_ip
 ***************************************************************************/
 
#ifndef _RC_FUNCS_H_
#define _RC_FUNCS_H_

#include "nivel1.h"

#define ETH_CRCLEN      2        /* Longitud en bytes del CRC   */
#define ETH_CRC_RESIDUO 0x0F47   /* Residuo al calcular el CRC  */

/*************************************************************************
 * Funcion: CalculaCRC
 * Fecha: 15.09.1998
 * Autor: Sergio Lopez
 *
 *  Funcion generica para el calculo del CRC de una secuencia de
 *  bits, suponiendo que el primer bit es el menos significativo
 *  de mensaje[0] y que el ultimo bit es el mas significativo de
 *  mensaje[longitud-1]. De igual manera, en el resultado el bit
 *  menos significativo es el primero del CRC.
 *
 *  Usa el polinomio generador del CCITT 1 + x5 + x12 + x16
 *
 * Entrada:
 *    unsigned longitud: Longitud del mensaje
 *    BYTE *mensaje: Mensaje del que se debe calcular el CRC
 *    BYTE *crc: Destino del CRC (2 bytes)
 * Salida:
 *    nada, y el 'crc' actualizado
 *************************************************************************/
void calcula_crc(unsigned longitud, BYTE *mensaje, BYTE *crc);

/***************************************************************************
 * Obtiene un checksum tipo IP a partir de un conjunto de bytes
 * entra:
 *   longitud - n. bytes de los datos sobre los que calcular el checksum
 *   datos - datos sobre los que calcular el checksum
 *   checksum - checksum de los datos (2 bytes)
 * sale:
 *   nada
 ***************************************************************************/
void calcula_checksum_ip(unsigned longitud, BYTE *datos, BYTE *checksum);

/****************************************************************************
 * Convierte una cadena de texto a una direccion Ethernet
 * entra:
 *   dir - una direccion en formato aa:bb:cc:dd:ee:ff
 *   eth - puntero a un BYTE[ETH_ALEN] donde escribir la dir. Ethernet obtenida
 * sale:
 *   -1 si error, 0 si todo bien (y la dir Ethernet bien copiada)
 ****************************************************************************/
int lee_cadena_eth(char *texto, BYTE *dir_eth);

/****************************************************************************
 * Convierte una cadena de texto a una direccion IP
 * entra:
 *   dir - una direccion en formato aaa.bbb.ccc.ddd
 *   ip - puntero a un BYTE[IP_ALEN] donde escribir la direccion IP obtenida
 * sale:
 *   -1 si error, 0 si todo bien (y la dir. IP bien copiada)
 ****************************************************************************/
int lee_cadena_ip(char *texto, BYTE *dir_ip);

#endif