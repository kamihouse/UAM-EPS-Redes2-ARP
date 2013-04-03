/***************************************************************************
 * arp.h 
 *
 *  Definiciones y cabeceras para el uso de ARP en las practicas de 
 *  Redes de Comunicaciones 2 de la EPS-UAM
 *
 *  Autor: Manuel Freire, Jose Hernandez
 *
 *  (C) 2006-07 EPS-UAM 
 ***************************************************************************/

#ifndef __ARP_H
#define __ARP_H

#include "nivel1.h"
#include "ip.h"

// numero maximo de entradas en cache ARP
#define ARP_CACHE_SIZE 10

// segundos de vida de una entrada ARP
#define ARP_CACHE_TTL 30

// direccion ethernet local
extern BYTE dir_eth_local[ETH_ALEN];

// global; ethertype de una trama ARP (definida en arp.c)
extern BYTE ethertype_arp[ETH_TLEN];

// prototipos publicos
/****************************************************************************
 * Muestra la cache ARP
 * entra / sale: nada
 ****************************************************************************/
void arp_muestra_cache();

/****************************************************************************
 * Inicializa ARP; debe llamarse antes de usar otras funciones de 'arp.h';
 * Se puede llamar muchas veces sin efectos adversos
 *
 * Lee la variable de entorno 'IPLOCAL' para determinar la IP local.
 *
 * entra: nada
 * sale:
 *   0 si todo bien, -1 en caso de error
 ****************************************************************************/
int arp_inicializa();

/****************************************************************************
 * Solicita la direccion Ethernet que corresponde a una direccion IP.
 * Si la direccion pedida ya esta en la cache, la devuelve sin mas.
 * En caso contrario, la solicita enviando una trama REQ, y reintentando
 * varias veces antes de desistir.
 *
 * entra:
 *    dir_ip - direccion IP
 *    dir_ether_pedida - direccion Ethernet a rellenar
 * sale:
 *    0 y dir_ether_pedida a su valor correspondiente, o -1 si error
 ****************************************************************************/
int arp_solicita_direccion(BYTE *dir_ip, BYTE *dir_eth_pedida);

/****************************************************************************
 * Procesa una trama Ethernet de tipo ARP
 * Si la direccion 'ip' del campo 'destino' es la propia,
 *    Si se trata de una consulta, envia una respuesta
 *    Si se trata de una respuesta, y el origen era la ip de una peticion 
 *       en curso, considera que ha satisfecho la peticion.
 * En cualquier caso, usa cualquier correspondencia ip/eth de la trama
 * para actualizar la propia cache ARP.
 *
 * entra:
 *    tamano, trama - longitud y datos de la trama ethernet recibida
 *    dir_eth_nivel1 - direccion ethernet origen de la trama recibida
 * sale:
 *    0 si no hay fallos, -1 en caso contrario
 ****************************************************************************/
int arp_procesa_trama(int tamano, BYTE *trama, BYTE *dir_eth_nivel1);


/****************************************************************************
 * Actualiza la cache ARP con una nueva entrada.
 * Si la entrada ya estaba presente, solo actualiza su 'tiempo de vida'
 * Si no tiene espacio para una nueva entrada, borra la entrada mas antigua.
 *
 * entra:
 *    dir_ip, dir_ether - direcciones a introducir en la nueva entrada
 * sale: nada
 ****************************************************************************/
void arp_actualiza_cache(BYTE *dir_ip, BYTE *dir_ether);

#endif // del #ifndef __ARP_H