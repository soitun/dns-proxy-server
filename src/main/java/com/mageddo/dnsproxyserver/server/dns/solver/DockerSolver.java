package com.mageddo.dnsproxyserver.server.dns.solver;

import com.mageddo.dnsproxyserver.docker.DockerRepository;
import com.mageddo.dnsproxyserver.utils.Ips;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Section;

import javax.inject.Inject;

@Slf4j
@AllArgsConstructor(onConstructor = @__({@Inject}))
public class DockerSolver implements Solver {

  private final DockerRepository dockerRepository;

  @Override
  public Message handle(Message reqMsg) {

//    questionName := question.Name[:len(question.Name)-1]
    final var question = reqMsg.getQuestion();
    final var questionName = question.getName().toString(true);

//    for _, host := range getAllHosts("." + questionName) {
//      if s.c.ContainsKey(host) {
//        return s.doSolve(ctx, host, question)
//      }
//    }
    for (final var host : Wildcards.buildHostAndWildcards(questionName)) {
      final var ip = this.dockerRepository.findHostIp(host);
      if (ip == null) {
        return null;
      }
      return this.toMsg(reqMsg, ip);
    }


//    func (s DockerDnsSolver) doSolve(ctx context.Context, k string, q dns.Question) (*dns.Msg, error) {
//      logging.Debugf("solver=docker, status=solved-key, question=%s, hostname=%s, ip=%+v", ctx, q.Name, k, s.c.Get(k))
//      return s.getMsg(k, q), nil
//    }
//
//    func NewDockerSolver(c cache.Cache) DockerDnsSolver {
//      return DockerDnsSolver{c}
//    }
//
//    func (s DockerDnsSolver) getMsg(key string, question dns.Question) *dns.Msg {
//      ip := s.c.Get(key).(string)
//          ipArr := strings.Split(ip, ".")
//      i1, _ := strconv.Atoi(ipArr[0])
//      i2, _ := strconv.Atoi(ipArr[1])
//      i3, _ := strconv.Atoi(ipArr[2])
//      i4, _ := strconv.Atoi(ipArr[3])
//
//      rr := &dns.A{
//        Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
//        A:   net.IPv4(byte(i1), byte(i2), byte(i3), byte(i4)),
//      }
//
//      m := new(dns.Msg)
//          m.Answer = append(m.Answer, rr)
//      return m
//    }


    return null;
  }

  Message toMsg(Message reqMsg, String ip) {
    final var res = new Message(reqMsg.getHeader().getID());
//     = Record.newRecord(reqMsg.getQuestion().getName(), Type.A, DClass.IN, 30, Ips.toBytes(ip));
    final var answer = new ARecord(reqMsg.getQuestion().getName(), DClass.IN, 30L, Ips.toAddress(ip));
    res.addRecord(answer, Section.ANSWER);
    return res;
  }

//  func (s DockerDnsSolver) getMsg(key string, question dns.Question) *dns.Msg {
//    ip := s.c.Get(key).(string)
//        ipArr := strings.Split(ip, ".")
//    i1, _ := strconv.Atoi(ipArr[0])
//    i2, _ := strconv.Atoi(ipArr[1])
//    i3, _ := strconv.Atoi(ipArr[2])
//    i4, _ := strconv.Atoi(ipArr[3])
//
//    rr := &dns.A{
//      Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
//      A:   net.IPv4(byte(i1), byte(i2), byte(i3), byte(i4)),
//    }
//
//    m := new(dns.Msg)
//        m.Answer = append(m.Answer, rr)
//    return m
//  }


  @Override
  public byte priority() {
    return Priority.ZERO;
  }
}
