/*
 * ZeroTier One - Network Virtualization Everywhere
 * Copyright (C) 2011-2016  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ZT_jniutils.h"

#include "ZT_jnicache.h"

#include <string>
#include <cassert>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#define LOG_TAG "Utils"

jobject createResultObject(JNIEnv *env, ZT_ResultCode code)
{
    jobject resultObject = env->CallStaticObjectMethod(ResultCode_class, ResultCode_fromInt_method, (jint)code);
    if(env->ExceptionCheck() || resultObject == NULL) {
        LOGE("Error creating ResultCode object");
        return NULL;
    }

    return resultObject;
}


jobject createVirtualNetworkStatus(JNIEnv *env, ZT_VirtualNetworkStatus status)
{
    jobject statusObject = env->CallStaticObjectMethod(VirtualNetworkStatus_class, VirtualNetworkStatus_fromInt_method, (jint)status);
    if (env->ExceptionCheck() || statusObject == NULL) {
        LOGE("Error creating VirtualNetworkStatus object");
        return NULL;
    }

    return statusObject;
}

jobject createEvent(JNIEnv *env, ZT_Event event)
{
    jobject eventObject = env->CallStaticObjectMethod(Event_class, Event_fromInt_method, (jint)event);
    if (env->ExceptionCheck() || eventObject == NULL) {
        LOGE("Error creating Event object");
        return NULL;
    }

    return eventObject;
}

jobject createPeerRole(JNIEnv *env, ZT_PeerRole role)
{
    jobject peerRoleObject = env->CallStaticObjectMethod(PeerRole_class, PeerRole_fromInt_method, (jint)role);
    if (env->ExceptionCheck() || peerRoleObject == NULL) {
        LOGE("Error creating PeerRole object");
        return NULL;
    }

    return peerRoleObject;
}

jobject createVirtualNetworkType(JNIEnv *env, ZT_VirtualNetworkType type)
{
    jobject vntypeObject = env->CallStaticObjectMethod(VirtualNetworkType_class, VirtualNetworkType_fromInt_method, (jint)type);
    if (env->ExceptionCheck() || vntypeObject == NULL) {
        LOGE("Error creating VirtualNetworkType object");
        return NULL;
    }

    return vntypeObject;
}

jobject createVirtualNetworkConfigOperation(JNIEnv *env, ZT_VirtualNetworkConfigOperation op)
{
    jobject vnetConfigOpObject = env->CallStaticObjectMethod(VirtualNetworkConfigOperation_class, VirtualNetworkConfigOperation_fromInt_method, (jint)op);
    if (env->ExceptionCheck() || vnetConfigOpObject == NULL) {
        LOGE("Error creating VirtualNetworkConfigOperation object");
        return NULL;
    }

    return vnetConfigOpObject;
}

jobject newInetAddress(JNIEnv *env, const sockaddr_storage &addr)
{
    jobject inetAddressObj = NULL;
    switch(addr.ss_family)
    {
        case AF_INET6:
        {
            sockaddr_in6 *ipv6 = (sockaddr_in6*)&addr;
            const unsigned char *bytes = reinterpret_cast<const unsigned char *>(&ipv6->sin6_addr.s6_addr);

            jbyteArray buff = newByteArray(env, bytes, 16);
            if(env->ExceptionCheck() || buff == NULL)
            {
                return NULL;
            }

            inetAddressObj = env->CallStaticObjectMethod(
                InetAddress_class, InetAddress_getByAddress_method, (jbyteArray)buff);
        }
        break;
        case AF_INET:
        {
            sockaddr_in *ipv4 = (sockaddr_in*)&addr;
            const unsigned char *bytes = reinterpret_cast<const unsigned char *>(&ipv4->sin_addr.s_addr);
            jbyteArray buff = newByteArray(env, bytes, 4);
            if(env->ExceptionCheck() || buff == NULL)
            {
                return NULL;
            }

            inetAddressObj = env->CallStaticObjectMethod(
                InetAddress_class, InetAddress_getByAddress_method, (jbyteArray)buff);
        }
        break;
        default:
        {
            assert(false && "addr.ss_family is neither AF_INET6 nor AF_INET");
        }
    }
    if(env->ExceptionCheck() || inetAddressObj == NULL) {
        LOGE("Error creating InetAddress object");
        return NULL;
    }

    return inetAddressObj;
}

int addressPort(const sockaddr_storage addr) {

    int port = 0;
    switch(addr.ss_family)
    {
        case AF_INET6:
        {
            sockaddr_in6 *ipv6 = (sockaddr_in6*)&addr;
            port = ntohs(ipv6->sin6_port);
        }
            break;
        case AF_INET:
        {
            sockaddr_in *ipv4 = (sockaddr_in*)&addr;
            port = ntohs(ipv4->sin_port);
        }
            break;
        default:
        {
            assert(false && "addr.ss_family is neither AF_INET6 nor AF_INET");
        }
    }

    return port;
}

//
// addr may be empty
//
// may return NULL
//
jobject newInetSocketAddress(JNIEnv *env, const sockaddr_storage &addr)
{
    if(isSocketAddressEmpty(addr))
    {
        return NULL;
    }

    jobject inetAddressObject = newInetAddress(env, addr);

    if(env->ExceptionCheck() || inetAddressObject == NULL)
    {
        return NULL;
    }

    int port = addressPort(addr);

    jobject inetSocketAddressObject = env->NewObject(InetSocketAddress_class, InetSocketAddress_ctor, (jobject)inetAddressObject, (jint)port);
    if(env->ExceptionCheck() || inetSocketAddressObject == NULL) {
        LOGE("Error creating InetSocketAddress object");
        return NULL;
    }
    return inetSocketAddressObject;
}

jobject newPeerPhysicalPath(JNIEnv *env, const ZT_PeerPhysicalPath &ppp)
{
    //
    // may be NULL
    //
    jobject addressObject = newInetSocketAddress(env, ppp.address);
    if(env->ExceptionCheck()) {
        return NULL;
    }

    jobject pppObject = env->NewObject(
            PeerPhysicalPath_class,
            PeerPhysicalPath_ctor,
            (jobject)addressObject,
            (jlong)ppp.lastSend,
            (jlong)ppp.lastReceive,
            (jboolean)ppp.preferred); // ANDROID-56: cast to correct size
    if(env->ExceptionCheck() || pppObject == NULL)
    {
        LOGE("Error creating PPP object");
        return NULL;
    }

    return pppObject;
}

jobject newPeer(JNIEnv *env, const ZT_Peer &peer)
{
    jobject peerRoleObj = createPeerRole(env, peer.role);
    if(env->ExceptionCheck() || peerRoleObj == NULL)
    {
        return NULL; // out of memory
    }

    jobjectArray arrayObject = newPeerPhysicalPathArray(env, peer.paths, peer.pathCount);
    if (env->ExceptionCheck() || arrayObject == NULL) {
        return NULL;
    }

    jobject peerObject = env->NewObject(
            Peer_class,
            Peer_ctor,
            (jlong)peer.address,
            (jint)peer.versionMajor,
            (jint)peer.versionMinor,
            (jint)peer.versionRev,
            (jint)peer.latency,
            (jobject)peerRoleObj,
            (jobjectArray)arrayObject);
    if(env->ExceptionCheck() || peerObject == NULL)
    {
        LOGE("Error creating Peer object");
        return NULL;
    }

    return peerObject;
}

jobject newNetworkConfig(JNIEnv *env, const ZT_VirtualNetworkConfig &vnetConfig)
{
    jstring nameStr = env->NewStringUTF(vnetConfig.name);
    if(env->ExceptionCheck() || nameStr == NULL)
    {
        LOGE("Exception creating new string");
        return NULL; // out of memory
    }

    jobject statusObject = createVirtualNetworkStatus(env, vnetConfig.status);
    if(env->ExceptionCheck() || statusObject == NULL)
    {
        return NULL;
    }

    jobject typeObject = createVirtualNetworkType(env, vnetConfig.type);
    if(env->ExceptionCheck() || typeObject == NULL)
    {
        return NULL;
    }

    jobjectArray assignedAddrArrayObj = newInetSocketAddressArray(env, vnetConfig.assignedAddresses, vnetConfig.assignedAddressCount);
    if (env->ExceptionCheck() || assignedAddrArrayObj == NULL) {
        return NULL;
    }

    jobjectArray routesArrayObj = newVirtualNetworkRouteArray(env, vnetConfig.routes, vnetConfig.routeCount);
    if (env->ExceptionCheck() || routesArrayObj == NULL) {
        return NULL;
    }

    //
    // may be NULL
    //
    jobject dnsObj = newVirtualNetworkDNS(env, vnetConfig.dns);
    if(env->ExceptionCheck()) {
        return NULL;
    }

    jobject vnetConfigObj = env->NewObject(
            VirtualNetworkConfig_class,
            VirtualNetworkConfig_ctor,
            (jlong)vnetConfig.nwid,
            (jlong)vnetConfig.mac,
            (jstring)nameStr,
            (jobject)statusObject,
            (jobject)typeObject,
            (jint)vnetConfig.mtu,
            (jboolean)vnetConfig.dhcp, // ANDROID-56: cast to correct size
            (jboolean)vnetConfig.bridge, // ANDROID-56: cast to correct size
            (jboolean)vnetConfig.broadcastEnabled, // ANDROID-56: cast to correct size
            (jint)vnetConfig.portError,
            (jlong)vnetConfig.netconfRevision,
            (jobjectArray)assignedAddrArrayObj,
            (jobjectArray)routesArrayObj,
            (jobject)dnsObj);
    if(env->ExceptionCheck() || vnetConfigObj == NULL)
    {
        LOGE("Error creating new VirtualNetworkConfig object");
        return NULL;
    }

    return vnetConfigObj;
}

jobject newVersion(JNIEnv *env, int major, int minor, int rev)
{
    // create a com.zerotier.sdk.Version object
    jobject versionObj = env->NewObject(Version_class, Version_ctor, (jint)major, (jint)minor, (jint)rev);
    if(env->ExceptionCheck() || versionObj == NULL)
    {
        LOGE("Error creating new Version object");
        return NULL;
    }

    return versionObj;
}

jobject newVirtualNetworkRoute(JNIEnv *env, const ZT_VirtualNetworkRoute &route)
{
    //
    // may be NULL
    //
    jobject targetObj = newInetSocketAddress(env, route.target);
    if (env->ExceptionCheck()) {
        return NULL;
    }

    //
    // may be NULL
    //
    jobject viaObj = newInetSocketAddress(env, route.via);
    if (env->ExceptionCheck()) {
        return NULL;
    }

    jobject routeObj = env->NewObject(
            VirtualNetworkRoute_class,
            VirtualNetworkRoute_ctor,
            (jobject)targetObj,
            (jobject)viaObj,
            (jint)route.flags, // ANDROID-56: cast to correct size
            (jint)route.metric); // ANDROID-56: cast to correct size
    if(env->ExceptionCheck() || routeObj == NULL)
    {
        LOGE("Exception creating VirtualNetworkRoute");
        return NULL;
    }

    return routeObj;
}

//
// may return NULL
//
jobject newVirtualNetworkDNS(JNIEnv *env, const ZT_VirtualNetworkDNS &dns)
{
    if (strlen(dns.domain) == 0) {
        LOGD("dns.domain is empty; returning NULL");
        return NULL;
    }

    jstring domain = env->NewStringUTF(dns.domain);
    if (env->ExceptionCheck() || domain == NULL) {
        LOGE("Exception creating new string");
        return NULL;
    }

    jobject addrList = env->NewObject(ArrayList_class, ArrayList_ctor, (jint)0);
    if (env->ExceptionCheck() || addrList == NULL) {
        LOGE("Exception creating new ArrayList");
        return NULL;
    }

    for (int i = 0; i < ZT_MAX_DNS_SERVERS; ++i) { //NOLINT

        struct sockaddr_storage tmp = dns.server_addr[i];

        //
        // may be NULL
        //
        jobject addr = newInetSocketAddress(env, tmp);
        if (env->ExceptionCheck()) {
            return NULL;
        }

        if (addr == NULL) {
            continue;
        }

        env->CallBooleanMethod(addrList, ArrayList_add_method, (jobject)addr);
        if(env->ExceptionCheck())
        {
            LOGE("Exception calling add");
            return NULL;
        }

        env->DeleteLocalRef(addr);
    }

    jobject dnsObj = env->NewObject(
            VirtualNetworkDNS_class,
            VirtualNetworkDNS_ctor,
            (jstring)domain,
            (jobject)addrList);
    if (env->ExceptionCheck() || dnsObj == NULL) {
        LOGE("Exception creating new VirtualNetworkDNS");
        return NULL;
    }
    return dnsObj;
}

jobject newNodeStatus(JNIEnv *env, const ZT_NodeStatus &status) {

    jstring pubIdentStr = env->NewStringUTF(status.publicIdentity);
    if(env->ExceptionCheck() || pubIdentStr == NULL)
    {
        LOGE("Exception creating new string");
        return NULL;
    }

    jstring secIdentStr = env->NewStringUTF(status.secretIdentity);
    if(env->ExceptionCheck() || secIdentStr == NULL)
    {
        LOGE("Exception creating new string");
        return NULL;
    }

    jobject nodeStatusObj = env->NewObject(
            NodeStatus_class,
            NodeStatus_ctor,
            (jlong)status.address,
            (jstring)pubIdentStr,
            (jstring)secIdentStr,
            (jboolean)status.online);
    if(env->ExceptionCheck() || nodeStatusObj == NULL) {
        LOGE("Exception creating new NodeStatus");
        return NULL;
    }

    return nodeStatusObj;
}

jobjectArray newPeerArray(JNIEnv *env, const ZT_Peer *peers, size_t count) {
    return newArrayObject<ZT_Peer, newPeer>(env, peers, count, Peer_class);
}

jobjectArray newVirtualNetworkConfigArray(JNIEnv *env, const ZT_VirtualNetworkConfig *networks, size_t count) {
    return newArrayObject<ZT_VirtualNetworkConfig, newNetworkConfig>(env, networks, count, VirtualNetworkConfig_class);
}

jobjectArray newPeerPhysicalPathArray(JNIEnv *env, const ZT_PeerPhysicalPath *paths, size_t count) {
    return newArrayObject<ZT_PeerPhysicalPath, newPeerPhysicalPath>(env, paths, count, PeerPhysicalPath_class);
}

jobjectArray newInetSocketAddressArray(JNIEnv *env, const sockaddr_storage *addresses, size_t count) {
    return newArrayObject<sockaddr_storage, newInetSocketAddress>(env, addresses, count, InetSocketAddress_class);
}

jobjectArray newVirtualNetworkRouteArray(JNIEnv *env, const ZT_VirtualNetworkRoute *routes, size_t count) {
    return newArrayObject<ZT_VirtualNetworkRoute, newVirtualNetworkRoute>(env, routes, count, VirtualNetworkRoute_class);
}

void newArrayObject_logCount(size_t count) {
    LOGE("count > JSIZE_MAX: %zu", count);
}

void newArrayObject_log(const char *msg) {
    LOGE("%s", msg);
}

jbyteArray newByteArray(JNIEnv *env, const unsigned char *bytes, size_t count) {

    if (count > JSIZE_MAX) {
        LOGE("count > JSIZE_MAX: %zu", count);
        return NULL;
    }

    jsize jCount = static_cast<jsize>(count);
    const jbyte *jBytes = reinterpret_cast<const jbyte *>(bytes);

    jbyteArray byteArrayObj = env->NewByteArray(jCount);
    if(byteArrayObj == NULL)
    {
        LOGE("NewByteArray returned NULL");
        return NULL;
    }

    env->SetByteArrayRegion(byteArrayObj, 0, jCount, jBytes);
    if (env->ExceptionCheck()) {
        LOGE("Exception when calling SetByteArrayRegion");
        return NULL;
    }

    return byteArrayObj;
}

jbyteArray newByteArray(JNIEnv *env, size_t count) {

    if (count > JSIZE_MAX) {
        LOGE("count > JSIZE_MAX: %zu", count);
        return NULL;
    }

    jsize jCount = static_cast<jsize>(count);

    jbyteArray byteArrayObj = env->NewByteArray(jCount);
    if(byteArrayObj == NULL)
    {
        LOGE("NewByteArray returned NULL");
        return NULL;
    }

    return byteArrayObj;
}

bool isSocketAddressEmpty(const sockaddr_storage addr) {

    //
    // was:
    // struct sockaddr_storage nullAddress = {0};
    //
    // but was getting this warning:
    // warning: suggest braces around initialization of subobject
    //
    // when building ZeroTierOne
    //
    sockaddr_storage emptyAddress; //NOLINT

    //
    // It is possible to assume knowledge about internals of sockaddr_storage and construct
    // correct 0-initializer, but it is simpler to just treat sockaddr_storage as opaque and
    // use memset here to fill with 0
    //
    // This is also done in InetAddress.hpp for InetAddress
    //
    memset(&emptyAddress, 0, sizeof(sockaddr_storage));

    return (memcmp(&addr, &emptyAddress, sizeof(sockaddr_storage)) == 0); //NOLINT
}

//
// returns empty sockaddr_storage on error
//
sockaddr_storage fromSocketAddressObject(JNIEnv *env, jobject sockAddressObject) {

    sockaddr_storage emptyAddress; //NOLINT

    memset(&emptyAddress, 0, sizeof(sockaddr_storage));

    jint port = env->CallIntMethod(sockAddressObject, InetSocketAddress_getPort_method);
    if(env->ExceptionCheck())
    {
        LOGE("Exception calling getPort");
        return emptyAddress;
    }

    jobject addressObject = env->CallObjectMethod(sockAddressObject, InetSocketAddress_getAddress_method);
    if(env->ExceptionCheck() || addressObject == NULL)
    {
        LOGE("Exception calling getAddress");
        return emptyAddress;
    }

    jbyteArray addressArrayObj = reinterpret_cast<jbyteArray>(env->CallObjectMethod(addressObject, InetAddress_getAddress_method));
    if(env->ExceptionCheck() || addressArrayObj == NULL)
    {
        LOGE("Exception calling getAddress");
        return emptyAddress;
    }

    sockaddr_storage addr = {};

    if (env->IsInstanceOf(addressObject, Inet4Address_class)) {

        // IPV4

        assert(env->GetArrayLength(addressArrayObj) == 4);

        sockaddr_in *addr_4 = reinterpret_cast<sockaddr_in *>(&addr);
        addr_4->sin_family = AF_INET;
        addr_4->sin_port = htons(port);

        void *data = env->GetPrimitiveArrayCritical(addressArrayObj, NULL);
        memcpy(&addr_4->sin_addr.s_addr, data, 4);
        env->ReleasePrimitiveArrayCritical(addressArrayObj, data, 0);

    } else if (env->IsInstanceOf(addressObject, Inet6Address_class)) {

        // IPV6

        assert(env->GetArrayLength(addressArrayObj) == 16);

        sockaddr_in6 *addr_6 = reinterpret_cast<sockaddr_in6 *>(&addr);
        addr_6->sin6_family = AF_INET6;
        addr_6->sin6_port = htons(port);

        void *data = env->GetPrimitiveArrayCritical(addressArrayObj, NULL);
        memcpy(&addr_6->sin6_addr.s6_addr, data, 16);
        env->ReleasePrimitiveArrayCritical(addressArrayObj, data, 0);

    } else {
        assert(false && "addressObject is neither Inet4Address nor Inet6Address");
    }

    return addr;
}
